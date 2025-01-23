use super::Zuc256Keystream;

/// ZUC256 stream cipher
/// ([ZUC256-version1.1](http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180416526664982687.pdf))
pub type Zuc256StreamCipher = cipher::StreamCipherCoreWrapper<Zuc256Keystream>;
