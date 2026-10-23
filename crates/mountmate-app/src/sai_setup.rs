//! Editor-only SAI setup; authentication never enters the mount service or saved settings.
use crate::i18n::Locale;
use iced::widget::{button, column, container, pick_list, text};
use iced::{Element, Fill, Task};
use mountmate_sai::{Client, ConfiguredConnection, Connection, Error, Login, Session};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Message {
    Start,
    Cancel,
    LoginStarted(u64, Result<Box<(Client, Login)>, Error>),
    Authorized(u64, Result<Arc<Session>, Error>),
    Select(Connection),
    Enroll,
    Finished(u64, Result<ConfiguredConnection, Error>),
    OpenBrowser,
    BrowserOpened(u64, bool),
}
#[derive(Default)]
pub struct State {
    generation: u64,
    task: Option<iced::task::Handle>,
    login: Option<Login>,
    session: Option<Arc<Session>>,
    selected: Option<Connection>,
    pending: bool,
    ready: bool,
    error: Option<Error>,
    browser_failed: bool,
}
impl State {
    pub fn reset(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        *self = Self {
            generation: self.generation.wrapping_add(1),
            ..Self::default()
        };
    }
    pub fn in_progress(&self) -> bool {
        self.pending || self.session.is_some()
    }
    fn track(&mut self, task: Task<Message>) -> Task<Message> {
        let (task, handle) = task.abortable();
        self.task = Some(handle.abort_on_drop());
        task
    }
    pub fn update(
        &mut self,
        message: Message,
        data_dir: &Path,
        locale: Locale,
    ) -> (Task<Message>, Option<ConfiguredConnection>) {
        match message {
            Message::Start if !self.pending => {
                self.reset();
                self.pending = true;
                let generation = self.generation;
                let task = Task::perform(
                    async {
                        let client = Client::discover().await?;
                        let login = client.start_login().await?;
                        Ok(Box::new((client, login)))
                    },
                    move |result| Message::LoginStarted(generation, result),
                );
                return (self.track(task), None);
            }
            Message::Cancel => self.reset(),
            Message::LoginStarted(generation, result) if generation == self.generation => {
                match result {
                    Ok(started) => {
                        let (client, login) = *started;
                        self.login = Some(login.clone());
                        let task = Task::perform(
                            async move { client.finish_login(&login).await.map(Arc::new) },
                            move |result| Message::Authorized(generation, result),
                        );
                        return (self.track(task), None);
                    }
                    Err(error) => {
                        self.pending = false;
                        self.error = Some(error);
                    }
                }
            }
            Message::Authorized(generation, result) if generation == self.generation => {
                self.pending = false;
                self.login = None;
                match result {
                    Ok(session) => {
                        self.selected = session.connections().first().cloned();
                        self.session = Some(session);
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Select(site) if !self.pending => {
                if self
                    .session
                    .as_ref()
                    .is_some_and(|s| s.connections().contains(&site))
                {
                    self.selected = Some(site);
                    self.error = None;
                }
            }
            Message::Enroll if !self.pending => {
                if let (Some(session), Some(site)) = (self.session.clone(), self.selected.clone()) {
                    self.pending = true;
                    self.error = None;
                    let generation = self.generation;
                    let data_dir = data_dir.to_owned();
                    let task = Task::perform(
                        async move { session.enroll(&site, &data_dir).await },
                        move |result| Message::Finished(generation, result),
                    );
                    return (self.track(task), None);
                }
            }
            Message::Finished(generation, result) if generation == self.generation => {
                self.pending = false;
                match result {
                    Ok(configured) => {
                        self.reset();
                        self.ready = true;
                        return (Task::none(), Some(configured));
                    }
                    Err(error) => {
                        if error == Error::Expired {
                            self.reset();
                        }
                        self.error = Some(error);
                    }
                }
            }
            Message::OpenBrowser => {
                if let Some(login) = &self.login {
                    let path = PathBuf::from(login.verification_url());
                    let generation = self.generation;
                    return (
                        Task::perform(
                            async move {
                                tokio::task::spawn_blocking(move || super::open_path(&path, locale))
                                    .await
                                    .is_ok_and(|result| result.is_ok())
                            },
                            move |ok| Message::BrowserOpened(generation, ok),
                        ),
                        None,
                    );
                }
            }
            Message::BrowserOpened(generation, ok) if generation == self.generation => {
                self.browser_failed = !ok
            }
            _ => {}
        }
        (Task::none(), None)
    }
    pub fn view(&self, locale: Locale) -> Element<'_, Message> {
        let tr = |en, zh| match locale {
            Locale::English => en,
            Locale::Chinese => zh,
        };
        let mut content = column![
            text(tr("Set up with a SAI account", "使用 SAI 账号配置")).size(18),
            text(tr("Sign in, choose a site, and register this device's public key to fill the connection settings.",
                "登录后选择站点，登记本机公钥，自动填写连接信息。")).size(14),
        ].spacing(10);
        if let Some(login) = &self.login {
            content = content
                .push(text(tr(
                    "Open the page and enter this code:",
                    "打开登录页面并输入验证码：",
                )))
                .push(text(login.verification_url()).size(14))
                .push(text(login.user_code()).size(24))
                .push(
                    button(tr("Open sign-in page", "打开登录页面")).on_press(Message::OpenBrowser),
                )
                .push(text(tr("Waiting for authorization…", "正在等待授权…")));
            if self.browser_failed {
                content = content.push(text(tr(
                    "Could not open the browser. Open the address above manually.",
                    "无法打开浏览器，请手动打开上方地址。",
                )));
            }
        } else if let Some(session) = &self.session {
            if session.connections().is_empty() {
                content = content.push(text(tr(
                    "This account has no available SSH sites. Check access in the SAI console.",
                    "此账号暂无可用的 SSH 站点，请在 SAI 控制台检查接入权限。",
                )));
            } else if self.pending {
                content = content.push(text(tr(
                    "Registering the public key and waiting for the site to apply it…",
                    "正在登记公钥，等待站点确认生效…",
                )));
            } else {
                content = content
                    .push(
                        pick_list(
                            session.connections().to_vec(),
                            self.selected.clone(),
                            Message::Select,
                        )
                        .width(Fill),
                    )
                    .push(
                        button(tr("Authorize this device", "授权此设备")).on_press(Message::Enroll),
                    );
            }
            content = content.push(text(tr("The private key stays on this device. After registration, cancelling setup or deleting a connection does not revoke access; remove the key in the SAI console.",
                "私钥保存在本机。登记后，取消配置或删除连接不会撤销授权；请在 SAI 控制台移除公钥。")).size(14));
        } else if self.pending {
            content = content.push(text(tr(
                "Checking service and starting sign-in…",
                "正在检查服务并发起登录…",
            )));
        } else {
            if self.ready {
                content = content.push(text(tr(
                    "Public key applied. Review the mount paths below and save the connection.",
                    "公钥已生效。请检查下方挂载路径并保存连接。",
                )));
            }
            content = content
                .push(button(tr("Sign in to SAI", "登录 SAI 账号")).on_press(Message::Start));
        }
        if let Some(error) = self.error {
            content = content.push(text(error_text(error, locale)));
        }
        if self.in_progress() {
            content = content
                .push(button(tr("Cancel account setup", "取消账号配置")).on_press(Message::Cancel));
        }
        container(content)
            .padding(16)
            .width(Fill)
            .style(container::rounded_box)
            .into()
    }
}
fn error_text(error: Error, locale: Locale) -> String {
    if locale == Locale::English {
        return error.to_string();
    }
    match error {
        Error::Unavailable => "SAI 服务尚未启用 MountMate 账号配置。你仍可在下方手动填写连接信息。",
        Error::Contract => "服务返回的连接信息不兼容或不可信，请联系 SAI 服务管理员。",
        Error::Network => "无法访问服务，请检查网络后重试。登记重试会使用原来的本机密钥。",
        Error::Authorization => "SAI 授权失败，请重新登录。",
        Error::Denied => "SAI 授权被拒绝。",
        Error::Expired => "SAI 授权已过期，请重新登录。",
        Error::Forbidden => "此账号无法执行该操作，请在 SAI 控制台检查 SSH 接入权限。",
        Error::KeyStorage => "无法安全创建或读取本机 SSH 密钥，请检查应用数据目录权限。",
        Error::SyncPending => "公钥仍在同步，请重试。重试会使用原来的本机密钥。",
        Error::SyncFailed => "服务未能将公钥应用到站点，请在 SAI 控制台检查。",
    }
    .into()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_generation_ignores_late_results() {
        let mut state = State::default();
        let generation = state.generation;
        state.reset();
        let _ = state.update(
            Message::LoginStarted(generation, Err(Error::Unavailable)),
            Path::new("unused"),
            Locale::English,
        );
        let _ = state.update(
            Message::Finished(generation, Err(Error::SyncFailed)),
            Path::new("unused"),
            Locale::English,
        );
        assert!(!state.in_progress());
        assert!(state.error.is_none());
        assert!(!state.ready);
    }
}
