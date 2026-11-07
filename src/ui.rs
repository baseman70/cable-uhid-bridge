use anyhow::Result;
use eframe::egui;
use qrcode::QrCode;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

pub const EXIT_CODE_CANCEL: i32 = 2;

pub enum UiCommand {
    Status(String),
    QrScanned,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemePalette {
    pub is_light: bool,
    pub background: egui::Color32,
    pub surface: egui::Color32,
    pub text_primary: egui::Color32,
    pub text_secondary: egui::Color32,
    pub accent: egui::Color32,
    pub success: egui::Color32,
    pub danger: egui::Color32,
}

impl Default for ThemePalette {
    fn default() -> Self {
        // Catppuccin Mocha fallback
        Self {
            is_light: false,
            background: egui::Color32::from_rgb(24, 24, 37),
            surface: egui::Color32::from_rgb(30, 30, 46),
            text_primary: egui::Color32::from_rgb(205, 214, 244),
            text_secondary: egui::Color32::from_rgb(186, 194, 222),
            accent: egui::Color32::from_rgb(137, 180, 250),
            success: egui::Color32::from_rgb(166, 227, 161),
            danger: egui::Color32::from_rgb(243, 139, 168),
        }
    }
}

pub fn parse_hex_color(hex: &str) -> Option<egui::Color32> {
    let clean = hex.trim().trim_matches('"').trim_matches('\'');
    let clean = clean.strip_prefix('#').unwrap_or(clean);
    if clean.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&clean[0..2], 16).ok()?;
    let g = u8::from_str_radix(&clean[2..4], 16).ok()?;
    let b = u8::from_str_radix(&clean[4..6], 16).ok()?;
    Some(egui::Color32::from_rgb(r, g, b))
}

impl ThemePalette {
    pub fn from_toml_str(content: &str) -> Self {
        let mut palette = Self::default();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"').trim_matches('\'');
                match key {
                    "mode" => {
                        palette.is_light = val.eq_ignore_ascii_case("light");
                    }
                    "background" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.background = c;
                        }
                    }
                    "lighter_background" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.surface = c;
                        }
                    }
                    "foreground" | "bright_foreground" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.text_primary = c;
                        }
                    }
                    "light_foreground" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.text_secondary = c;
                        }
                    }
                    "accent" | "blue" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.accent = c;
                        }
                    }
                    "green" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.success = c;
                        }
                    }
                    "red" => {
                        if let Some(c) = parse_hex_color(val) {
                            palette.danger = c;
                        }
                    }
                    _ => {}
                }
            }
        }
        palette
    }

    pub fn load_system_or_default() -> Self {
        let mut candidates = Vec::new();
        if let Ok(xdg_state) = std::env::var("XDG_STATE_HOME") {
            candidates.push(PathBuf::from(xdg_state).join("omarchy/current/theme/colors.toml"));
        }
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(home);
            candidates.push(home_path.join(".local/state/omarchy/current/theme/colors.toml"));
            candidates.push(home_path.join(".config/omarchy/current/theme/colors.toml"));
        }
        for path in candidates {
            if let Ok(content) = std::fs::read_to_string(&path) {
                return Self::from_toml_str(&content);
            }
        }
        Self::default()
    }
}

pub struct CableModalApp {
    rp_id: String,
    is_registration: bool,
    status: String,
    is_success: bool,
    qr_scanned: bool,
    qr_texture: egui::TextureHandle,
    palette: ThemePalette,
    cmd_rx: mpsc::Receiver<UiCommand>,
    dismiss_at: Option<Instant>,
}

impl CableModalApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        rp_id: String,
        url: String,
        is_registration: bool,
        cmd_rx: mpsc::Receiver<UiCommand>,
    ) -> Self {
        // Generate high-contrast QR code
        let qr = QrCode::new(url.as_bytes()).unwrap_or_else(|_| QrCode::new(b"error").unwrap());
        let width = qr.width();
        let border = 2;
        let total_size = width + border * 2;

        let mut rgba = vec![255u8; total_size * total_size * 4]; // white background
        for (y, row) in qr.to_colors().chunks(width).enumerate() {
            for (x, &color) in row.iter().enumerate() {
                let px = x + border;
                let py = y + border;
                let idx = (py * total_size + px) * 4;
                if color == qrcode::Color::Dark {
                    rgba[idx] = 18;
                    rgba[idx + 1] = 18;
                    rgba[idx + 2] = 20;
                    rgba[idx + 3] = 255;
                }
            }
        }

        let color_image = egui::ColorImage::from_rgba_unmultiplied([total_size, total_size], &rgba);

        let qr_texture =
            cc.egui_ctx
                .load_texture("cable_qr_code", color_image, egui::TextureOptions::NEAREST);

        let palette = ThemePalette::load_system_or_default();

        // Configure visuals from active theme palette
        let mut visuals = if palette.is_light {
            egui::Visuals::light()
        } else {
            egui::Visuals::dark()
        };
        visuals.override_text_color = Some(palette.text_primary);
        visuals.panel_fill = palette.background;
        visuals.widgets.noninteractive.bg_fill = palette.surface;
        cc.egui_ctx.set_visuals(visuals);

        Self {
            rp_id,
            is_registration,
            status: "Scan QR code with your phone camera".into(),
            is_success: false,
            qr_scanned: false,
            qr_texture,
            palette,
            cmd_rx,
            dismiss_at: None,
        }
    }

    fn trigger_cancel(&self, ctx: &egui::Context) {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(b"CANCEL\n");
        let _ = stdout.flush();
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        std::process::exit(EXIT_CODE_CANCEL);
    }
}

fn draw_phone_connected_icon(ui: &mut egui::Ui, accent: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(38.0, 56.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let body = rect.shrink2(egui::vec2(4.0, 2.0));
    painter.rect_stroke(
        body,
        egui::CornerRadius::same(6),
        egui::Stroke::new(2.5, egui::Color32::from_rgb(30, 30, 46)),
        egui::StrokeKind::Inside,
    );
    // Speaker notch
    let top_center = egui::pos2(body.center().x, body.top() + 6.0);
    painter.line_segment(
        [
            egui::pos2(top_center.x - 5.0, top_center.y),
            egui::pos2(top_center.x + 5.0, top_center.y),
        ],
        egui::Stroke::new(2.0, egui::Color32::from_rgb(108, 112, 134)),
    );
    // Center Bluetooth/Check badge inside phone screen
    let center = body.center();
    painter.circle_filled(center, 10.0, accent);
    painter.line_segment(
        [
            egui::pos2(center.x - 4.0, center.y + 0.5),
            egui::pos2(center.x - 1.0, center.y + 3.5),
        ],
        egui::Stroke::new(2.2, egui::Color32::WHITE),
    );
    painter.line_segment(
        [
            egui::pos2(center.x - 1.0, center.y + 3.5),
            egui::pos2(center.x + 4.5, center.y - 3.0),
        ],
        egui::Stroke::new(2.2, egui::Color32::WHITE),
    );
}

impl eframe::App for CableModalApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Read incoming commands from stdin worker
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                UiCommand::Status(s) => self.status = s,
                UiCommand::QrScanned => {
                    self.qr_scanned = true;
                    self.status = "Phone connected! Waiting for Face ID / Touch ID...".into();
                }
                UiCommand::Done => {
                    self.is_success = true;
                    self.status = "Done!".into();
                    self.dismiss_at = Some(Instant::now());
                }
            }
        }

        // Allow pressing Escape to cancel
        if !self.is_success && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.trigger_cancel(ui.ctx());
            return;
        }

        // Handle auto-close only when the transaction has finished successfully
        if let Some(dismiss_time) = self.dismiss_at {
            if dismiss_time.elapsed().as_millis() > 500 {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        }

        // Request repaint for smooth spinner and timer
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(50));

        let header_title = if self.is_registration {
            "🔑 Passkey Registration"
        } else {
            "🔑 Passkey Authentication"
        };

        ui.vertical_centered(|ui| {
            ui.add_space(14.0);

            // Header Title
            ui.label(
                egui::RichText::new(header_title)
                    .size(17.0)
                    .strong()
                    .color(self.palette.text_primary),
            );

            ui.add_space(6.0);

            // RP Badge (constrained to content width)
            ui.horizontal(|ui| {
                let badge_width = (self.rp_id.len() as f32 * 8.2 + 28.0).clamp(90.0, 300.0);
                let side_pad = ((ui.available_width() - badge_width) * 0.5).max(0.0);
                ui.add_space(side_pad);
                egui::Frame::new()
                    .fill(self.palette.surface)
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(12, 4))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(&self.rp_id)
                                .color(self.palette.accent)
                                .strong()
                                .size(14.0),
                        );
                    });
            });

            ui.add_space(12.0);

            // QR Code in Centered Square White Card (244x244 outer, 220x220 inner)
            let card_outer = 244.0;
            ui.allocate_ui_with_layout(
                egui::vec2(card_outer, card_outer),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    egui::Frame::new()
                        .fill(egui::Color32::WHITE)
                        .corner_radius(egui::CornerRadius::same(12))
                        .inner_margin(egui::Margin::same(12))
                        .show(ui, |ui| {
                            let size = egui::vec2(220.0, 220.0);
                            if !self.qr_scanned {
                                ui.image((self.qr_texture.id(), size));
                            } else {
                                ui.allocate_ui_with_layout(
                                    size,
                                    egui::Layout::top_down(egui::Align::Center),
                                    |ui| {
                                        ui.add_space(34.0);
                                        draw_phone_connected_icon(ui, self.palette.accent);
                                        ui.add_space(12.0);
                                        ui.label(
                                            egui::RichText::new("Phone Connected")
                                                .color(egui::Color32::from_rgb(30, 30, 46))
                                                .strong()
                                                .size(16.0),
                                        );
                                        ui.add_space(6.0);
                                        ui.label(
                                            egui::RichText::new("Confirm on your phone...")
                                                .color(egui::Color32::from_rgb(108, 112, 134))
                                                .size(12.5),
                                        );
                                    },
                                );
                            }
                        });
                },
            );

            ui.add_space(14.0);

            // Status indicator and text
            ui.horizontal(|ui| {
                ui.add_space(22.0);
                if !self.is_success {
                    ui.add(egui::Spinner::new().size(14.0).color(self.palette.accent));
                } else {
                    ui.label(
                        egui::RichText::new("✓")
                            .color(self.palette.success)
                            .size(16.0)
                            .strong(),
                    );
                }
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(&self.status)
                        .size(13.0)
                        .color(if self.is_success {
                            self.palette.success
                        } else {
                            self.palette.text_secondary
                        }),
                );
            });

            ui.add_space(14.0);

            // Cancel Button
            if !self.is_success {
                let cancel_btn = egui::Button::new(
                    egui::RichText::new("Cancel (Esc)")
                        .color(self.palette.danger)
                        .size(13.0),
                )
                .fill(self.palette.surface)
                .corner_radius(egui::CornerRadius::same(6))
                .min_size(egui::vec2(104.0, 28.0));

                if ui.add(cancel_btn).clicked() {
                    self.trigger_cancel(ui.ctx());
                }
            }
        });
    }
}

impl Drop for CableModalApp {
    fn drop(&mut self) {
        if !self.is_success {
            std::process::exit(EXIT_CODE_CANCEL);
        }
    }
}

pub fn run_ui(rp_id: String, url: String, is_registration: bool) -> Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::channel();

    // Background thread to listen for stdin updates from daemon
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let reader = BufReader::new(stdin);
        for line in reader.lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if trimmed == "QR_SCANNED" || trimmed == "DISMISS" {
                    let _ = cmd_tx.send(UiCommand::QrScanned);
                } else if trimmed == "DONE" {
                    let _ = cmd_tx.send(UiCommand::Done);
                    break;
                } else if let Some(status) = trimmed.strip_prefix("STATUS:") {
                    let _ = cmd_tx.send(UiCommand::Status(status.to_string()));
                }
            } else {
                break;
            }
        }
    });

    let title = if is_registration {
        "Passkey Registration"
    } else {
        "Passkey Authentication"
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("cable-uhid-bridge")
            .with_title(title)
            .with_inner_size([340.0, 410.0])
            .with_min_inner_size([340.0, 410.0])
            .with_max_inner_size([340.0, 410.0])
            .with_resizable(false)
            .with_always_on_top(),
        ..Default::default()
    };

    eframe::run_native(
        title,
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(CableModalApp::new(
                cc,
                rp_id,
                url,
                is_registration,
                cmd_rx,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("Failed to run UI: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_color_valid() {
        assert_eq!(
            parse_hex_color("#7aa2f7"),
            Some(egui::Color32::from_rgb(0x7a, 0xa2, 0xf7))
        );
        assert_eq!(
            parse_hex_color("\"#1a1b26\""),
            Some(egui::Color32::from_rgb(0x1a, 0x1b, 0x26))
        );
        assert_eq!(
            parse_hex_color("a6e3a1"),
            Some(egui::Color32::from_rgb(0xa6, 0xe3, 0xa1))
        );
    }

    #[test]
    fn test_parse_hex_color_invalid() {
        assert_eq!(parse_hex_color(""), None);
        assert_eq!(parse_hex_color("#123"), None);
        assert_eq!(parse_hex_color("#zzzzzz"), None);
    }

    #[test]
    fn test_theme_palette_from_omarchy_toml() {
        let toml = r##"
mode = "dark"
accent = "#7aa2f7"
background = "#1a1b26"
lighter_background = "#24283b"
foreground = "#a9b1d6"
light_foreground = "#b4bee6"
bright_foreground = "#c0caf5"
red = "#f7768e"
green = "#9ece6a"
"##;
        let palette = ThemePalette::from_toml_str(toml);
        assert!(!palette.is_light);
        assert_eq!(
            palette.background,
            egui::Color32::from_rgb(0x1a, 0x1b, 0x26)
        );
        assert_eq!(palette.surface, egui::Color32::from_rgb(0x24, 0x28, 0x3b));
        assert_eq!(palette.accent, egui::Color32::from_rgb(0x7a, 0xa2, 0xf7));
        assert_eq!(palette.success, egui::Color32::from_rgb(0x9e, 0xce, 0x6a));
        assert_eq!(palette.danger, egui::Color32::from_rgb(0xf7, 0x76, 0x8e));
    }

    #[test]
    fn test_theme_palette_light_mode() {
        let toml = r##"
mode = "light"
background = "#eff1f5"
"##;
        let palette = ThemePalette::from_toml_str(toml);
        assert!(palette.is_light);
        assert_eq!(
            palette.background,
            egui::Color32::from_rgb(0xef, 0xf1, 0xf5)
        );
    }
}
