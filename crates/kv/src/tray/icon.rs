//! The tray's icon, drawn in code so the binary carries no image files: a
//! key, dimmed while locked, with a badge while requests wait. macOS draws
//! it as a template image (alpha only), so it follows the menu bar; there
//! the waiting count is the title beside the icon instead of the badge.

use super::model::IconState;

/// Width and height in pixels.
pub const SIZE: u32 = 32;

const ON: [u8; 3] = [0x10, 0xb9, 0x81];
const OFF: [u8; 3] = [0x80, 0x80, 0x80];
/// How opaque the key is while locked.
const OFF_ALPHA: f32 = 0.6;
const BADGE: [u8; 3] = [0xef, 0x44, 0x44];

/// The icon for `state`, as RGBA rows of `SIZE` pixels.
pub fn rgba(state: IconState) -> Vec<u8> {
    let (color, alpha) = match state {
        IconState::Off | IconState::Locked => (OFF, OFF_ALPHA),
        IconState::Unlocked | IconState::Waiting(_) => (ON, 1.0),
    };
    let badged = matches!(state, IconState::Waiting(_));
    let mut image = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let key = coverage(x, y, in_key) * alpha;
            let badge = if badged {
                coverage(x, y, in_badge)
            } else {
                0.0
            };
            // The badge over the key.
            let total = badge + key * (1.0 - badge);
            let channel = |i: usize| {
                if total == 0.0 {
                    0
                } else {
                    let mixed = BADGE[i] as f32 * badge + color[i] as f32 * key * (1.0 - badge);
                    (mixed / total).round() as u8
                }
            };
            image.extend([
                channel(0),
                channel(1),
                channel(2),
                (total * 255.0).round() as u8,
            ]);
        }
    }
    image
}

/// How much of pixel (x, y) lies inside the shape, from 16 samples.
fn coverage(x: u32, y: u32, inside: fn(f32, f32) -> bool) -> f32 {
    let mut hits = 0;
    for i in 0..4 {
        for j in 0..4 {
            let sx = x as f32 + (i as f32 + 0.5) / 4.0;
            let sy = y as f32 + (j as f32 + 0.5) / 4.0;
            if inside(sx, sy) {
                hits += 1;
            }
        }
    }
    hits as f32 / 16.0
}

/// A key lying on its side: a ring on the left, the shaft to the right,
/// two teeth below it.
fn in_key(x: f32, y: f32) -> bool {
    let ring = ((x - 9.5).powi(2) + (y - 16.0).powi(2)).sqrt();
    let rect = |left: f32, top: f32, right: f32, bottom: f32| {
        (left..right).contains(&x) && (top..bottom).contains(&y)
    };
    (3.0..7.0).contains(&ring)
        || rect(15.5, 14.5, 29.0, 17.5)
        || rect(21.5, 17.5, 24.0, 22.0)
        || rect(26.5, 17.5, 29.0, 20.5)
}

fn in_badge(x: f32, y: f32) -> bool {
    let (cx, cy) = (SIZE as f32 - 6.5, 6.5);
    (x - cx).powi(2) + (y - cy).powi(2) < 36.0
}
