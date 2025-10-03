use crate::app::{
    Message,
    server_page::{ServerPage, ServerPageMessage},
};
use iced::{
    Length, Task,
    alignment::{Horizontal, Vertical},
    widget::{button, column, container, row, text, text_input, toggler},
};
use iced_aw::number_input;

impl ServerPage {
    fn setting_header_width() -> Length {
        Length::Fixed(150.0)
    }

    fn setting_row_height() -> Length {
        Length::Fixed(30.0)
    }

    fn setting_port_row(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        row![
            text("Port")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            number_input(&self.config.port, 1..=u16::MAX, |p| {
                Message::ServerPageMsg(ServerPageMessage::PortChanged(p))
            })
            .style(number_input::number_input::primary)
            .step(1)
        ]
        .height(row_height)
        .into()
    }
    
    fn setting_workers(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        row![
            text("Upload workers")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            number_input(&self.config.worker_count, 1..=16, |p| {
                Message::ServerPageMsg(ServerPageMessage::WorkersChanged(p))
            })
            .style(number_input::number_input::primary)
            .step(1)
        ]
        .height(row_height)
        .into()
    }

    fn setting_greeting_row(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        row![
            text("Greeting")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            text_input("", &self.config.greeting)
                .on_input(|g| { Message::ServerPageMsg(ServerPageMessage::GreetingChanged(g)) }),
        ]
        .height(row_height)
        .into()
    }

    fn setting_tls_row(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        row![
            text("TLS")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            container(
                toggler(self.config.tls)
                    .on_toggle(|t| Message::ServerPageMsg(ServerPageMessage::TLSChanged(t))),
            )
            .align_y(Vertical::Center)
            .height(Length::Fill),
        ]
        .height(row_height)
        .into()
    }

    fn setting_auth_json_row(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        let auth_json: &str = self
            .config
            .auth_json
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("");

        row![
            text("JSON user auth file")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            button("Select").on_press(Message::ServerPageMsg(ServerPageMessage::AuthJsonPick)),
            text(auth_json)
                .align_y(Vertical::Center)
                .height(Length::Fill),
        ]
        .height(row_height)
        .into()
    }

    fn setting_tls_cert_row(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        let tls_cert: &str = self
            .config
            .tls_cert
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("");

        row![
            text("TLS Certificate")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            button("Select").on_press(Message::ServerPageMsg(ServerPageMessage::TLSCertPick)),
            text(tls_cert)
                .align_y(Vertical::Center)
                .height(Length::Fill),
        ]
        .height(row_height)
        .into()
    }

    fn setting_tls_key_row(
        &self,
        header_width: Length,
        row_height: Length,
    ) -> iced::Element<'_, Message> {
        let tls_key: &str = self
            .config
            .tls_key
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("");

        row![
            text("TLS Key")
                .width(header_width)
                .align_y(Vertical::Center)
                .height(Length::Fill),
            button("Select").on_press(Message::ServerPageMsg(ServerPageMessage::TLSKeyPick)),
            text(tls_key).align_y(Vertical::Center).height(Length::Fill),
        ]
        .height(row_height)
        .into()
    }

    #[allow(clippy::unused_self)]
    fn setting_start_button(&self) -> iced::Element<'_, Message> {
        container(button("Start server").on_press(Message::ServerPageMsg(ServerPageMessage::Start)))
            .width(Length::Fill)
            .align_x(Horizontal::Right)
            .into()
    }

    pub(super) fn settings_view(&self) -> iced::Element<'_, Message> {
        let header_width = Self::setting_header_width();
        let row_height = Self::setting_row_height();

        let content = column![
            self.setting_port_row(header_width, row_height),
            self.setting_greeting_row(header_width, row_height),
            self.setting_auth_json_row(header_width, row_height),
            self.setting_tls_row(header_width, row_height),
            self.setting_tls_cert_row(header_width, row_height),
            self.setting_tls_key_row(header_width, row_height),
            self.setting_workers(header_width, row_height),
            self.setting_start_button(),
        ]
        .spacing(10)
        .height(Length::Shrink)
        .width(Length::FillPortion(3));

        row![
            text("").width(Length::FillPortion(1)),
            content,
            text("").width(Length::FillPortion(1)),
        ]
        .into()
    }

    #[allow(clippy::unused_self)]
    pub(super) fn pick_auth_json(&self) -> Task<Message> {
        Task::future(async {
            if let Some(file) = rfd::AsyncFileDialog::new()
                .set_title("JSON user authentication file")
                .add_filter("json", &["json"])
                .pick_file()
                .await
            {
                let path = file.path().to_path_buf();
                Message::ServerPageMsg(ServerPageMessage::AuthJsonChanged(path))
            } else {
                Message::None
            }
        })
    }

    #[allow(clippy::unused_self)]
    pub(super) fn pick_key(&self) -> Task<Message> {
        Task::future(async {
            if let Some(file) = rfd::AsyncFileDialog::new()
                .set_title("TLS Key")
                .pick_file()
                .await
            {
                let path = file.path().to_path_buf();
                Message::ServerPageMsg(ServerPageMessage::TLSKeyChanged(path))
            } else {
                Message::None
            }
        })
    }

    #[allow(clippy::unused_self)]
    pub(super) fn pick_cert(&self) -> Task<Message> {
        Task::future(async {
            if let Some(file) = rfd::AsyncFileDialog::new()
                .set_title("TLS Certificate")
                .pick_file()
                .await
            {
                let path = file.path().to_path_buf();
                Message::ServerPageMsg(ServerPageMessage::TLSCertChanged(path))
            } else {
                Message::None
            }
        })
    }
}
