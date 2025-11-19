// Licensed under the Apache-2.0 license

#![allow(dead_code)]

mod test_jtag_taps;
mod test_lc_transitions;
mod test_manuf_debug_unlock;
mod test_uds;

#[cfg(test)]
mod test {
    use caliptra_hw_model::jtag::CaliptraCoreReg;
    use caliptra_hw_model::Fuses;
    use mcu_builder::FirmwareBinaries;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    use std::sync::OnceLock;

    static CALIPTRA_CORE_ALWAYS_UNLOCKED_DMI_REGS: OnceLock<Vec<CaliptraCoreReg>> = OnceLock::new();
    static CALIPTRA_CORE_DEFAULT_LOCKED_DMI_REGS: OnceLock<Vec<CaliptraCoreReg>> = OnceLock::new();

    pub fn get_cc_always_unlocked_dmi_regs() -> &'static Vec<CaliptraCoreReg> {
        let mut s: Vec<CaliptraCoreReg> = Vec::new();
        CALIPTRA_CORE_ALWAYS_UNLOCKED_DMI_REGS.get_or_init(|| {
            s.push(CaliptraCoreReg::MboxDlen);
            s.push(CaliptraCoreReg::MboxDout);
            s.push(CaliptraCoreReg::MboxStatus);
            s.push(CaliptraCoreReg::MboxCmd);
            s.push(CaliptraCoreReg::MboxLock);
            s.push(CaliptraCoreReg::MboxDin);
            s.push(CaliptraCoreReg::MboxExecute);
            s.push(CaliptraCoreReg::BootStatus);
            s.push(CaliptraCoreReg::CptraHwErrrorEnc);
            s.push(CaliptraCoreReg::CptraFwErrorEnc);
            s.push(CaliptraCoreReg::BootfsmGo);
            s.push(CaliptraCoreReg::CptraDbgManufServiceReg);
            s.push(CaliptraCoreReg::HwFatalError);
            s.push(CaliptraCoreReg::FwFatalError);
            s.push(CaliptraCoreReg::HwNonFatalError);
            s.push(CaliptraCoreReg::FwNonFatalError);
            s.push(CaliptraCoreReg::SsDbgManufServiceRegReq);
            s.push(CaliptraCoreReg::SsDbgManufServiceRegRsp);
            s
        })
    }

    pub fn get_cc_default_locked_dmi_regs() -> &'static Vec<CaliptraCoreReg> {
        CALIPTRA_CORE_DEFAULT_LOCKED_DMI_REGS.get_or_init(|| {
            let mut s: Vec<CaliptraCoreReg> = Vec::new();
            s.push(CaliptraCoreReg::SsUdsSeedBaseAddrL);
            s.push(CaliptraCoreReg::SsUdsSeedBaseAddrH);
            s.push(CaliptraCoreReg::SsDebugIntent);
            s.push(CaliptraCoreReg::SsCaliptraBaseAddrL);
            s.push(CaliptraCoreReg::SsCaliptraBaseAddrH);
            s.push(CaliptraCoreReg::SsMciBaseAddrL);
            s.push(CaliptraCoreReg::SsMciBaseAddrH);
            s.push(CaliptraCoreReg::SsRecoveryIfcBaseAddrL);
            s.push(CaliptraCoreReg::SsRecoveryIfcBaseAddrH);
            s.push(CaliptraCoreReg::SsExternalStagingAreaBaseAddrL);
            s.push(CaliptraCoreReg::SsExternalStagingAreaBaseAddrH);
            s.push(CaliptraCoreReg::SsOtpFcBaseAddrL);
            s.push(CaliptraCoreReg::SsOtpFcBaseAddrH);
            s.push(CaliptraCoreReg::SsStrapCaliptraDmaAxiUser);
            s.push(CaliptraCoreReg::SsStrapGeneric0);
            s.push(CaliptraCoreReg::SsStrapGeneric1);
            s.push(CaliptraCoreReg::SsStrapGeneric2);
            s.push(CaliptraCoreReg::SsStrapGeneric3);
            s.push(CaliptraCoreReg::SsDbgUnlockLevel0);
            s.push(CaliptraCoreReg::SsDbgUnlockLevel1);
            s
        })
    }

    pub fn ss_setup(
        initial_lc_state: Option<LifecycleControllerState>,
        rma_or_scrap_ppd: bool,
        debug_intent: bool,
        bootfsm_break: bool,
        enable_mcu_uart_log: bool,
    ) -> DefaultHwModel {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();

        let init_params = InitParams {
            fuses: Fuses::default(),
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: initial_lc_state,
            rma_or_scrap_ppd,
            debug_intent,
            bootfsm_break,
            enable_mcu_uart_log,
            ..Default::default()
        };
        DefaultHwModel::new_unbooted(init_params).unwrap()
    }
}
