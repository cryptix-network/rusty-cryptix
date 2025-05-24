use crate::notification::Notification;
use cryptix_notify::{collector::CollectorFrom, converter::ConverterFrom};

pub type ConsensusConverter = ConverterFrom<Notification, Notification>;
pub type ConsensusCollector = CollectorFrom<ConsensusConverter>;
