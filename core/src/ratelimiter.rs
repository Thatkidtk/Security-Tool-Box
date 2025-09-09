use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct RateLimiter {
    sem: Arc<Semaphore>,
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self { RateLimiter { sem: self.sem.clone() } }
}

impl RateLimiter {
    pub fn new(tokens_per_sec: u32) -> Self {
        let sem = Arc::new(Semaphore::new(0));
        let sem_bg = sem.clone();
        let interval_ms = (1000u32 / tokens_per_sec.max(1)) as u64;
        // Refill in a background task
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                sem_bg.add_permits(1);
            }
        });
        RateLimiter { sem }
    }

    pub async fn acquire(&self) {
        let _ = self.sem.acquire().await;
    }
}

