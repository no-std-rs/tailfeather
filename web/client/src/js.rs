//! The little the runtime needs from the browser beyond WebSockets: a clock,
//! timers, randomness, `localStorage`, `fetch`, and a wake-up signal between
//! tasks. Everything is single-threaded and runs on the page's event loop.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

/// Milliseconds since the Unix epoch on a monotonic clock:
/// `performance.timeOrigin + performance.now()`.
///
/// The node's reconnect and WireGuard timers and smoltcp's retransmissions all
/// run on this clock, so it must never step backwards when the system clock is
/// adjusted, or deadlines set before the change would stall until wall time
/// caught up. It is anchored at page load, which keeps it close enough to wall
/// time for trusted time and WireGuard timestamps.
pub fn now_ms() -> u64 {
    match web_sys::window().and_then(|window| window.performance()) {
        Some(performance) => (performance.time_origin() + performance.now()) as u64,
        None => js_sys::Date::now() as u64,
    }
}

/// Cryptographically secure randomness from `crypto.getRandomValues`.
pub fn fill_random(out: &mut [u8]) {
    getrandom::fill(out).expect("crypto.getRandomValues is available");
}

pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// One source of randomness for every tailfeather trait that wants one.
pub struct JsRng;

impl tailfeather::keys::Rng for JsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }
}

impl tailfeather::tunnel::Rng for JsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }
}

impl tailfeather::disco::packet::Rng for JsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }
}

impl tailfeather::derp::client::Rng for JsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = setTimeout)]
    fn set_timeout(handler: &js_sys::Function, ms: i32) -> i32;
    #[wasm_bindgen(js_name = clearTimeout)]
    fn clear_timeout(id: i32);
}

struct SleepState {
    done: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

/// A `setTimeout` future. Dropping it clears the timer, so racing it against
/// other work does not leave callbacks behind.
pub struct Sleep {
    ms: i32,
    state: Rc<SleepState>,
    armed: Option<(i32, Closure<dyn FnMut()>)>,
}

pub fn sleep(ms: u32) -> Sleep {
    Sleep {
        ms: ms.min(i32::MAX as u32) as i32,
        state: Rc::new(SleepState {
            done: Cell::new(false),
            waker: RefCell::new(None),
        }),
        armed: None,
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.state.done.get() {
            return Poll::Ready(());
        }
        *self.state.waker.borrow_mut() = Some(cx.waker().clone());
        if self.armed.is_none() {
            let state = self.state.clone();
            let closure = Closure::<dyn FnMut()>::new(move || {
                state.done.set(true);
                if let Some(waker) = state.waker.borrow_mut().take() {
                    waker.wake();
                }
            });
            let id = set_timeout(closure.as_ref().unchecked_ref(), self.ms);
            self.armed = Some((id, closure));
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some((id, _closure)) = self.armed.take()
            && !self.state.done.get()
        {
            clear_timeout(id);
        }
    }
}

/// Run `future` for at most `ms` milliseconds.
pub async fn timeout<F: Future>(ms: u32, future: F) -> Result<F::Output, ()> {
    let future = std::pin::pin!(future);
    match futures::future::select(future, sleep(ms)).await {
        futures::future::Either::Left((output, _)) => Ok(output),
        futures::future::Either::Right(_) => Err(()),
    }
}

#[derive(Default)]
struct NotifyState {
    notified: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

/// A level-triggered wake-up for one waiting task. Notifications coalesce.
#[derive(Clone, Default)]
pub struct Notify(Rc<NotifyState>);

impl Notify {
    pub fn notify(&self) {
        self.0.notified.set(true);
        if let Some(waker) = self.0.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| {
            if self.0.notified.replace(false) {
                Poll::Ready(())
            } else {
                *self.0.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        })
    }
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

pub fn storage_get(key: &str) -> Option<String> {
    storage()?.get_item(key).ok().flatten()
}

pub fn storage_set(key: &str, value: &str) -> bool {
    storage().is_some_and(|storage| storage.set_item(key, value).is_ok())
}

pub fn storage_remove(key: &str) {
    if let Some(storage) = storage() {
        let _ = storage.remove_item(key);
    }
}

/// Describe a JavaScript exception without assuming its shape.
pub fn describe(value: &JsValue) -> String {
    if let Some(error) = value.dyn_ref::<js_sys::Error>() {
        return String::from(error.message());
    }
    value
        .as_string()
        .unwrap_or_else(|| "JavaScript error".to_string())
}

/// `GET` a JSON document and return one string member of it.
pub async fn fetch_json_string(url: &str, member: &str) -> Result<String, String> {
    let window = web_sys::window().ok_or("no window")?;
    let response = wasm_bindgen_futures::JsFuture::from(window.fetch_with_str(url))
        .await
        .map_err(|error| format!("fetch {url}: {}", describe(&error)))?;
    let response: web_sys::Response = response
        .dyn_into()
        .map_err(|_| "fetch returned something other than a Response".to_string())?;
    if !response.ok() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let json = wasm_bindgen_futures::JsFuture::from(
        response
            .json()
            .map_err(|error| format!("{url}: {}", describe(&error)))?,
    )
    .await
    .map_err(|error| format!("{url}: {}", describe(&error)))?;
    js_sys::Reflect::get(&json, &JsValue::from_str(member))
        .ok()
        .and_then(|value| value.as_string())
        .ok_or_else(|| format!("{url}: no {member} in the response"))
}

/// Read an optional string member of a JavaScript options object.
pub fn get_string(object: &JsValue, member: &str) -> Option<String> {
    js_sys::Reflect::get(object, &JsValue::from_str(member))
        .ok()
        .and_then(|value| value.as_string())
}

pub fn get_bool(object: &JsValue, member: &str) -> Option<bool> {
    js_sys::Reflect::get(object, &JsValue::from_str(member))
        .ok()
        .and_then(|value| value.as_bool())
}

pub fn get_number(object: &JsValue, member: &str) -> Option<f64> {
    js_sys::Reflect::get(object, &JsValue::from_str(member))
        .ok()
        .and_then(|value| value.as_f64())
}

pub fn get_function(object: &JsValue, member: &str) -> Option<js_sys::Function> {
    js_sys::Reflect::get(object, &JsValue::from_str(member))
        .ok()
        .and_then(|value| value.dyn_into().ok())
}
