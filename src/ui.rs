use anyhow::Result;
use eframe::egui;
use qrcode::QrCode;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::Instant;

pub const EXIT_CODE_CANCEL: i32 = 2;

pub enum UiCommand {
    Status(String),
    QrScanned,
    Done,
}

pub struct CableModalApp {
    rp_id: String,
    status: String,
    is_success: bool,
    qr_scanned: bool,
    qr_texture: egui::TextureHandle,
    cmd_rx: mpsc::Receiver<UiCommand>,
    dismiss_at: Option<Instant>,
}

impl CableModalApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        rp_id: String,
        url: String,
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

        let color_image = egui::ColorImage::from_rgba_unmultiplied(
            [total_size, total_size],
            &rgba,
        );

        let qr_texture = cc.egui_ctx.load_texture(
            "cable_qr_code",
            color_image,
            egui::TextureOptions::NEAREST,
        );

        // Configure visuals for clean dark theme
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(egui::Color32::from_rgb(220, 224, 232));
        visuals.panel_fill = egui::Color32::from_rgb(24, 24, 37); // Catppuccin Mocha Base
        cc.egui_ctx.set_visuals(visuals);

        Self {
            rp_id,
            status: "Scan QR code with your phone camera".into(),
            is_success: false,
            qr_scanned: false,
            qr_texture,
            cmd_rx,
            dismiss_at: None,
        }
    }
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

        // Handle auto-close only when the transaction has finished successfully
        if let Some(dismiss_time) = self.dismiss_at {
            if dismiss_time.elapsed().as_millis() > 500 {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        }

        // Request repaint for smooth spinner and timer
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));

        ui.vertical_centered(|ui| {
            ui.add_space(16.0);

            // Header Title
            ui.label(
                egui::RichText::new("🔑 Passkey Authentication")
                    .size(17.0)
                    .strong()
                    .color(egui::Color32::from_rgb(205, 214, 244)),
            );

            ui.add_space(6.0);

            // RP Badge
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(30, 30, 46))
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(12, 4))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(&self.rp_id)
                            .color(egui::Color32::from_rgb(137, 180, 250))
                            .strong()
                            .size(14.0),
                    );
                });

            ui.add_space(14.0);

            // QR Code in White Card Container
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
                                ui.add_space(40.0);
                                ui.label(
                                    egui::RichText::new("📱")
                                        .size(44.0),
                                );
                                ui.add_space(8.0);
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
                                        .size(12.0),
                                );
                            },
                        );
                    }
                });

            ui.add_space(16.0);

            // Status indicator and text
            ui.horizontal(|ui| {
                ui.add_space(18.0);
                if !self.is_success {
                    ui.add(egui::Spinner::new().size(14.0));
                } else {
                    ui.label(
                        egui::RichText::new("✓")
                            .color(egui::Color32::from_rgb(166, 227, 161))
                            .size(16.0)
                            .strong(),
                    );
                }
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(&self.status)
                        .size(13.0)
                        .color(if self.is_success {
                            egui::Color32::from_rgb(166, 227, 161)
                        } else {
                            egui::Color32::from_rgb(186, 194, 222)
                        }),
                );
            });

            ui.add_space(18.0);

            // Cancel Button
            if !self.is_success {
                let cancel_btn = egui::Button::new(
                    egui::RichText::new("Cancel")
                        .color(egui::Color32::from_rgb(243, 139, 168))
                        .size(13.0),
                )
                .corner_radius(egui::CornerRadius::same(6))
                .min_size(egui::vec2(90.0, 28.0));

                if ui.add(cancel_btn).clicked() {
                    let mut stdout = std::io::stdout();
                    let _ = stdout.write_all(b"CANCEL\n");
                    let _ = stdout.flush();
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    std::process::exit(EXIT_CODE_CANCEL);
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

pub fn run_ui(rp_id: String, url: String) -> Result<()> {
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

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Passkey Authentication")
            .with_inner_size([350.0, 480.0])
            .with_resizable(false)
            .with_always_on_top(),
        ..Default::default()
    };

    eframe::run_native(
        "Passkey Authentication",
        native_options,
        Box::new(move |cc| Ok(Box::new(CableModalApp::new(cc, rp_id, url, cmd_rx)))),
    ).map_err(|e| anyhow::anyhow!("Failed to run UI: {:?}", e))
}
