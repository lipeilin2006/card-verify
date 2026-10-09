//! VMProtect SDK 区域标记。`vmp` feature 关闭时全部为 no-op；开启时
//! 编译进 VMProtectSDK64 桩调用，供 VMProtect 按 Begin/End 圈定保护。

#[cfg(feature = "vmp")]
#[allow(dead_code)]
mod sys {
    unsafe extern "C" {
        pub fn VMProtectBeginMutation(name: *const i8);
        pub fn VMProtectBeginVirtualization(name: *const i8);
        pub fn VMProtectEnd();
    }
}

#[cfg(feature = "vmp")]
#[allow(dead_code)]
#[inline(always)]
pub fn begin_mutation(name: &'static [u8]) {
    unsafe { sys::VMProtectBeginMutation(name.as_ptr() as *const i8) }
}

#[cfg(feature = "vmp")]
#[inline(always)]
pub fn begin_virtualization(name: &'static [u8]) {
    unsafe { sys::VMProtectBeginVirtualization(name.as_ptr() as *const i8) }
}

#[cfg(feature = "vmp")]
#[inline(always)]
pub fn end() {
    unsafe { sys::VMProtectEnd() }
}

#[cfg(not(feature = "vmp"))]
#[allow(dead_code)]
#[inline(always)]
pub fn begin_mutation(_name: &'static [u8]) {}

#[cfg(not(feature = "vmp"))]
#[inline(always)]
pub fn begin_virtualization(_name: &'static [u8]) {}

#[cfg(not(feature = "vmp"))]
#[inline(always)]
pub fn end() {}
