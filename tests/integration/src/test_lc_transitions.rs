// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_hw_model::BootParams;
    use mcu_builder::FirmwareBinaries;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    #[test]
    fn test_raw_unlock() {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();
        let lifecycle_controller_state = Some(LifecycleControllerState::TestUnlocked0);

        // Instantiate a CaliptaSS model with OTP empty, emulating a raw device.
        let mut _model = DefaultHwModel::new(
            InitParams {
                caliptra_rom: &firmware_bundle.caliptra_rom,
                mcu_rom: &firmware_bundle.mcu_rom,
                lifecycle_controller_state,
                ..Default::default()
            },
            BootParams {
                fw_image: Some(&firmware_bundle.caliptra_fw),
                soc_manifest: Some(&firmware_bundle.soc_manifest),
                mcu_fw_image: Some(&firmware_bundle.mcu_runtime),
                ..Default::default()
            },
        )
        .unwrap();

        // TODO(timothytrippel): add LC transition logic here.
    }
}
