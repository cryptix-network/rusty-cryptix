use crate::Notification;

pub type ChannelConnection = cryptix_notify::connection::ChannelConnection<Notification>;
pub use cryptix_notify::connection::ChannelType;
