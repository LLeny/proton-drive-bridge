use iced::{widget::text, Task};

use crate::app::Page;


pub(crate) struct NonePage {}

impl NonePage {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl Page for NonePage {
    fn update(&mut self, message: super::Message) -> Task<super::Message> {
        Task::done(message)
    }

    fn view(&'_ self) -> iced::Element<'_, super::Message> {
       text("Nothing to sees here.").into() 
    }
    
    fn subscription(&self) -> iced::Subscription<super::Message> {
        iced::Subscription::none() 
    }
}