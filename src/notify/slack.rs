extern crate slack_hook;
use dotenv::dotenv;
use slack_hook::{PayloadBuilder, Slack};
use std::env;

pub struct SlackNotify {}

impl SlackNotify {
    // Check if Slack is configured.
    pub fn check_setting() -> bool {
        dotenv().ok();
        if env::var("CHANNEL").is_err() {
            eprintln!("Channel not found");
            return false;
        }

        if env::var("WEBHOOK_URL").is_err() {
            eprintln!("WEBHOOK_URL not found");
            return false;
        }
        true
    }

    // send message to slack.
    pub fn notify(msg: String) -> Result<(), String> {
        dotenv().ok();
        if !SlackNotify::check_setting() {
            return Ok(());
        }

        let channel = env::var("CHANNEL").expect("CHANNEL is not found");
        let webhook_url = env::var("WEBHOOK_URL").expect("WEBHOOK_URL is not found");
        let ret = SlackNotify::_send_to_slack(msg, &channel, &webhook_url);
        if ret.is_ok() {
            Ok(())
        } else {
            Err("Slack Notification Failed.".to_string())
        }
    }

    fn _send_to_slack(
        msg: String,
        channel: &str,
        webhook_url: &str,
    ) -> Result<(), slack_hook::Error> {
        let slack = Slack::new(webhook_url).unwrap();
        let p = PayloadBuilder::new()
            .text(msg)
            .channel(channel)
            .username("hayabusa Notify Bot")
            .icon_emoji(":scream:")
            .build()
            .unwrap();

        slack.send(&p)
    }
}
