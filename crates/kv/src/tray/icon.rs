//! kv's mark, drawn in code so the binary carries no image files: a white
//! key on a violet tile (`docs/images/logo.svg` is the same drawing). The
//! tray dims the tile to grey while locked and adds a badge while requests
//! wait. macOS draws the tray icon as a template image (alpha only), so it
//! follows the menu bar: there the key is cut out of the tile, and the
//! waiting count is the title beside the icon instead of the badge.

use super::model::IconState;

/// The tray icon's width and height in pixels.
pub const SIZE: u32 = 32;

/// The window icon's width and height in pixels.
pub const LOGO_SIZE: u32 = 64;

/// The tile's gradient, top left to bottom right.
const VIOLET: ([u8; 3], [u8; 3]) = ([0x8b, 0x6c, 0xff], [0x5b, 0x3f, 0xd9]);
const GREY: ([u8; 3], [u8; 3]) = ([0x9a, 0x96, 0xb3], [0x6f, 0x6b, 0x8a]);
const KEY: [u8; 3] = [0xff, 0xff, 0xff];
const BADGE: [u8; 3] = [0xef, 0x44, 0x44];
/// How opaque the grey tile is while locked, or with no daemon or vault.
const OFF_ALPHA: f32 = 0.6;

/// The tray icon for `state`, as RGBA rows of `SIZE` pixels.
pub fn rgba(state: IconState) -> Vec<u8> {
    let (tile, alpha) = match state {
        IconState::Off | IconState::Locked => (GREY, OFF_ALPHA),
        IconState::Unlocked | IconState::Waiting(_) => (VIOLET, 1.0),
    };
    let template = cfg!(target_os = "macos");
    draw(
        SIZE,
        tile,
        alpha,
        matches!(state, IconState::Waiting(_)),
        template,
    )
}

/// The mark in colour, unlocked, as RGBA rows of `LOGO_SIZE` pixels: for
/// kv's window.
pub fn logo_rgba() -> Vec<u8> {
    draw(LOGO_SIZE, VIOLET, 1.0, false, false)
}

/// The tile `size` pixels square. A template keeps only the alpha: the
/// tile with the key cut out.
fn draw(size: u32, tile: ([u8; 3], [u8; 3]), alpha: f32, badged: bool, template: bool) -> Vec<u8> {
    // The drawing is 64 units square.
    let scale = 64.0 / size as f32;
    let mut image = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let at = |inside: fn(f32, f32) -> bool| coverage(x, y, scale, inside);
            let square = at(in_tile) * alpha;
            let key = at(in_key);
            let badge = if badged { at(in_badge) } else { 0.0 };
            let ring = if badged { at(in_badge_ring) } else { 0.0 };
            // How far along the gradient this pixel is.
            let t = ((x + y) as f32 / (2 * size - 2).max(1) as f32).clamp(0.0, 1.0);
            let shade = |i: usize| tile.0[i] as f32 + (tile.1[i] as f32 - tile.0[i] as f32) * t;
            // Back to front: the tile, the key on it, a gap round the badge,
            // the badge.
            let mut pixel = Pixel::default();
            if template {
                // Alpha only: the key is a hole in the tile.
                pixel.paint([0.0; 3], square * (1.0 - key));
            } else {
                pixel.paint([shade(0), shade(1), shade(2)], square);
                pixel.paint(KEY.map(f32::from), key * square);
                if badged {
                    // A clear ring keeps the badge apart from the tile.
                    pixel.erase(ring);
                    pixel.paint(BADGE.map(f32::from), badge);
                }
            }
            image.extend(pixel.rgba());
        }
    }
    image
}

/// One pixel, painted back to front: its colour premultiplied by how much
/// of it is covered.
#[derive(Default)]
struct Pixel {
    color: [f32; 3],
    cover: f32,
}

impl Pixel {
    /// `rgb` over what is there, covering `a` of the pixel.
    fn paint(&mut self, rgb: [f32; 3], a: f32) {
        for (c, new) in self.color.iter_mut().zip(rgb) {
            *c = new * a + *c * (1.0 - a);
        }
        self.cover = a + self.cover * (1.0 - a);
    }

    /// Clears `a` of the pixel.
    fn erase(&mut self, a: f32) {
        for c in &mut self.color {
            *c *= 1.0 - a;
        }
        self.cover *= 1.0 - a;
    }

    fn rgba(&self) -> [u8; 4] {
        let channel = |c: f32| {
            if self.cover == 0.0 {
                0
            } else {
                (c / self.cover).round().clamp(0.0, 255.0) as u8
            }
        };
        [
            channel(self.color[0]),
            channel(self.color[1]),
            channel(self.color[2]),
            (self.cover * 255.0).round() as u8,
        ]
    }
}

/// How much of pixel (x, y) lies inside the shape, from 16 samples, with
/// the shape in 64-unit space and `scale` units to a pixel.
fn coverage(x: u32, y: u32, scale: f32, inside: fn(f32, f32) -> bool) -> f32 {
    let mut hits = 0;
    for i in 0..4 {
        for j in 0..4 {
            let sx = (x as f32 + (i as f32 + 0.5) / 4.0) * scale;
            let sy = (y as f32 + (j as f32 + 0.5) / 4.0) * scale;
            if inside(sx, sy) {
                hits += 1;
            }
        }
    }
    hits as f32 / 16.0
}

/// Inside a rectangle with rounded corners of radius `r`.
fn in_rounded(x: f32, y: f32, left: f32, top: f32, right: f32, bottom: f32, r: f32) -> bool {
    if !(left..right).contains(&x) || !(top..bottom).contains(&y) {
        return false;
    }
    let cx = x.clamp(left + r, right - r);
    let cy = y.clamp(top + r, bottom - r);
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}

/// The tile: 60 units square with rounded corners.
fn in_tile(x: f32, y: f32) -> bool {
    in_rounded(x, y, 2.0, 2.0, 62.0, 62.0, 15.0)
}

/// A key lying on its side: a ring on the left, the shaft to the right,
/// two teeth below it.
fn in_key(x: f32, y: f32) -> bool {
    let ring = ((x - 23.0).powi(2) + (y - 32.0).powi(2)).sqrt();
    (5.0..11.0).contains(&ring)
        || in_rounded(x, y, 32.0, 29.0, 53.0, 35.0, 3.0)
        || in_rounded(x, y, 42.0, 31.0, 47.0, 42.0, 1.5)
        || in_rounded(x, y, 49.0, 31.0, 53.0, 39.0, 1.5)
}

fn in_badge(x: f32, y: f32) -> bool {
    (x - 51.0).powi(2) + (y - 13.0).powi(2) < 13.0f32.powi(2)
}

fn in_badge_ring(x: f32, y: f32) -> bool {
    (x - 51.0).powi(2) + (y - 13.0).powi(2) < 17.0f32.powi(2)
}
