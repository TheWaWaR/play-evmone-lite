use std::alloc::{dealloc, Layout};
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::slice::from_raw_parts;

use evmc_sys as ffi;
use hex;
use serde;

/// EVMC call kind.
pub type CallKind = ffi::evmc_call_kind;

/// EVMC status code.
pub type StatusCode = ffi::evmc_status_code;

/// EVMC storage status.
pub type StorageStatus = ffi::evmc_storage_status;

/// EVMC VM revision.
pub type Revision = ffi::evmc_revision;

pub type TxContext = ffi::evmc_tx_context;
pub type HostInterface = ffi::evmc_host_interface;

pub struct EvmcVm {
    pub instance: *mut ffi::evmc_vm,
}

impl EvmcVm {
    pub fn new(instance: *mut ffi::evmc_vm) -> EvmcVm {
        EvmcVm { instance }
    }

    pub fn execute(
        &self,
        revision: Revision,
        code: &[u8],
        message: &ExecutionMessage,
        context: &mut ExecutionContext,
    ) -> ExecutionResult {
        let result = unsafe {
            let execute_fn = (*self.instance).execute.clone().unwrap();
            execute_fn(
                self.instance,
                context.const_interface(),
                context.context,
                revision,
                message.as_ptr(),
                code.as_ptr(),
                code.len(),
            )
        };
        ExecutionResult::from(result)
    }
}

#[macro_export]
macro_rules! impl_serde {
    ($struct:ident, $visitor:ident, $parse_bytes:path) => {
        struct $visitor;

        impl<'b> serde::de::Visitor<'b> for $visitor {
            type Value = $struct;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a 0x-prefixed hex string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes = if &v.as_bytes()[0..2] == b"0x" {
                    &v.as_bytes()[2..]
                } else {
                    &v.as_bytes()[..]
                };
                if bytes.len() & 1 != 0 {
                    return Err(E::invalid_length(bytes.len(), &"odd length"));
                }
                $parse_bytes(bytes).map_err(E::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        impl serde::Serialize for $struct {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let output = format!("0x{}", hex::encode(&self.0));
                serializer.serialize_str(output.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $struct {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_str($visitor)
            }
        }
    };
}

macro_rules! impl_convert {
    ($struct:ident, $visitor:ident, $inner:ty, $target:path, $parse_bytes:path) => {
        #[derive(Eq, Default, Clone)]
        pub struct $struct(pub $inner);

        impl ::std::cmp::PartialEq for $struct {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl ::std::hash::Hash for $struct {
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
                state.write(&self.0[..]);
                // self.0.hash(state);
            }
        }
        impl From<$target> for $struct {
            fn from(data: $target) -> $struct {
                $struct(data.bytes)
            }
        }
        impl From<$struct> for $target {
            fn from(data: $struct) -> $target {
                $target { bytes: data.0 }
            }
        }
        impl ::std::fmt::Debug for $struct {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
                let prefix = if f.alternate() { "0x" } else { "" };
                write!(f, "{}{}", prefix, hex::encode(self.0))
            }
        }
        impl ::std::ops::Deref for $struct {
            type Target = [u8];
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl ::std::ops::DerefMut for $struct {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl_serde!($struct, $visitor, $parse_bytes);
    };
}

fn parse_bytes<T: Default + DerefMut<Target = [u8]> + Sized>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() / 2 != std::mem::size_of::<T>() {
        return Err(format!("length not expected: {}", bytes.len()));
    }
    let mut target = T::default();
    let inner: &mut [u8] = &mut target;
    hex::decode_to_slice(bytes, inner).map_err(|e| e.to_string())?;
    Ok(target)
}

impl_convert!(
    Address,
    AddressVisitor,
    [u8; 20],
    ffi::evmc_address,
    parse_bytes
);
impl_convert!(
    Bytes32,
    Bytes32Visitor,
    [u8; 32],
    ffi::evmc_bytes32,
    parse_bytes
);
// Big Endian
impl_convert!(
    Uint256,
    Uint256Visitor,
    [u8; 32],
    ffi::evmc_uint256be,
    parse_bytes
);

pub struct ExecutionResult {
    pub status_code: StatusCode,
    pub gas_left: i64,
    pub output_data: Vec<u8>,
    pub release: ffi::evmc_release_result_fn,
    pub create_address: Address,
    pub padding: [u8; 4],
}

impl fmt::Debug for ExecutionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output_data_hex = hex::encode(&self.output_data);
        f.debug_struct("ExecutionResult")
            .field("status_code", &self.status_code)
            .field("gas_left", &self.gas_left)
            .field("output_data", &output_data_hex)
            .field("release", &format_args!("{:?}", &self.release))
            .field("create_address", &self.create_address)
            .field("padding", &format_args!("{:?}", &self.padding))
            .finish()
    }
}

impl From<ffi::evmc_result> for ExecutionResult {
    fn from(result: ffi::evmc_result) -> ExecutionResult {
        let output_data = unsafe { from_raw_parts(result.output_data, result.output_size) };
        ExecutionResult {
            status_code: result.status_code,
            gas_left: result.gas_left,
            output_data: output_data.to_vec(),
            release: result.release,
            create_address: result.create_address.into(),
            padding: result.padding,
        }
    }
}
impl From<ExecutionResult> for ffi::evmc_result {
    fn from(result: ExecutionResult) -> ffi::evmc_result {
        let output_size = result.output_data.len();
        let output_data = result.output_data.as_ptr();
        ffi::evmc_result {
            status_code: result.status_code,
            gas_left: result.gas_left,
            output_data,
            output_size,
            release: result.release,
            create_address: result.create_address.into(),
            padding: result.padding,
        }
    }
}

pub struct ExecutionContext {
    pub interface: ffi::evmc_host_interface,
    pub context: *mut ffi::evmc_host_context,
}

impl ExecutionContext {
    pub fn new(
        interface: ffi::evmc_host_interface,
        context: *mut ffi::evmc_host_context,
    ) -> ExecutionContext {
        ExecutionContext { interface, context }
    }

    pub fn const_interface(&self) -> *const ffi::evmc_host_interface {
        (&self.interface) as *const ffi::evmc_host_interface
    }
}

#[derive(Debug)]
pub struct ExecutionMessage<'a> {
    pub inner: &'a ffi::evmc_message,
}

impl<'a> From<&'a ffi::evmc_message> for ExecutionMessage<'a> {
    fn from(inner: &'a ffi::evmc_message) -> ExecutionMessage<'a> {
        ExecutionMessage { inner }
    }
}

impl<'a> Deref for ExecutionMessage<'a> {
    type Target = ffi::evmc_message;
    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a> ExecutionMessage<'a> {
    pub fn as_ptr(&self) -> *const ffi::evmc_message {
        self.inner as *const ffi::evmc_message
    }
}

pub struct HostContextPtr<T> {
    pub ptr: *mut ffi::evmc_host_context,
    _data: PhantomData<T>,
}

impl<T: Sized> Drop for HostContextPtr<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(self.ptr);
            dealloc(self.ptr as *mut u8, Layout::new::<T>());
        }
    }
}

impl<T: HostContext + Sized> From<Box<T>> for HostContextPtr<T> {
    fn from(ctx: Box<T>) -> HostContextPtr<T> {
        let ptr = Box::into_raw(ctx) as *mut ffi::evmc_host_context;
        HostContextPtr {
            ptr,
            _data: PhantomData,
        }
    }
}

pub struct HostContextWrapper<T> {
    inner: Option<Box<T>>,
}

impl<T> Drop for HostContextWrapper<T> {
    fn drop(&mut self) {
        std::mem::forget(self.inner.take().unwrap());
    }
}

impl<T: HostContext> From<*mut ffi::evmc_host_context> for HostContextWrapper<T> {
    fn from(ptr: *mut ffi::evmc_host_context) -> HostContextWrapper<T> {
        let inner = Some(unsafe { Box::from_raw(ptr as *mut T) });
        HostContextWrapper { inner }
    }
}

impl<T: HostContext> Deref for HostContextWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<T: HostContext> DerefMut for HostContextWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

pub trait HostContext {
    fn interface() -> HostInterface;

    fn get_tx_context(&mut self) -> TxContext;
    fn account_exists(&mut self, address: &Address) -> bool;
    fn get_storage(&mut self, address: &Address, key: &Bytes32) -> Bytes32;
    fn set_storage(&mut self, address: Address, key: Bytes32, value: Bytes32) -> StorageStatus;
    fn get_balance(&mut self, address: &Address) -> Uint256;
    fn call(&mut self, msg: ExecutionMessage) -> ExecutionResult;
    fn selfdestruct(&mut self, address: &Address, beneficiary: &Address);
    fn emit_log(&mut self, address: &Address, data: &[u8], topics: &[Bytes32]);
    fn copy_code(&mut self, address: &Address, code_offset: usize, buffer: &[u8]) -> usize;
    fn get_code_size(&mut self, address: &Address) -> usize;
    fn get_code_hash(&mut self, address: &Address) -> Bytes32;
    fn get_block_hash(&mut self, number: u64) -> Bytes32;
}

pub fn get_interface<T: HostContext>() -> ffi::evmc_host_interface {
    unsafe extern "C" fn account_exists<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
    ) -> bool {
        let address = Address::from(*address);
        HostContextWrapper::<T>::from(context).account_exists(&address)
    }

    unsafe extern "C" fn get_tx_context<T: HostContext>(
        context: *mut ffi::evmc_host_context,
    ) -> ffi::evmc_tx_context {
        HostContextWrapper::<T>::from(context).get_tx_context()
    }

    unsafe extern "C" fn get_storage<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
        key: *const ffi::evmc_bytes32,
    ) -> ffi::evmc_bytes32 {
        let address = Address::from(*address);
        let key = Bytes32::from(*key);
        HostContextWrapper::<T>::from(context)
            .get_storage(&address, &key)
            .into()
    }

    unsafe extern "C" fn set_storage<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
        key: *const ffi::evmc_bytes32,
        value: *const ffi::evmc_bytes32,
    ) -> ffi::evmc_storage_status {
        let address = Address::from(*address);
        let key = Bytes32::from(*key);
        let value = Bytes32::from(*value);
        HostContextWrapper::<T>::from(context).set_storage(address, key, value)
    }

    unsafe extern "C" fn get_balance<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
    ) -> ffi::evmc_uint256be {
        let address = Address::from(*address);
        HostContextWrapper::<T>::from(context)
            .get_balance(&address)
            .into()
    }

    unsafe extern "C" fn call<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        msg: *const ffi::evmc_message,
    ) -> ffi::evmc_result {
        let message = ExecutionMessage::from(&*msg);
        HostContextWrapper::<T>::from(context).call(message).into()
    }

    unsafe extern "C" fn emit_log<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
        data: *const u8,
        data_size: usize,
        topics: *const ffi::evmc_bytes32,
        topics_count: usize,
    ) {
        let address = Address::from(*address);
        let data: &[u8] = from_raw_parts(data, data_size);
        let topics: &[ffi::evmc_bytes32] = from_raw_parts(topics, topics_count);
        let topics: &[Bytes32] =
            &*(topics as *const [evmc_sys::evmc_bytes32] as *const [Bytes32]);
        HostContextWrapper::<T>::from(context).emit_log(&address, data, topics)
    }

    unsafe extern "C" fn get_code_size<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
    ) -> usize {
        let address = Address::from(*address);
        HostContextWrapper::<T>::from(context).get_code_size(&address)
    }

    unsafe extern "C" fn get_code_hash<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
    ) -> ffi::evmc_bytes32 {
        let address = Address::from(*address);
        HostContextWrapper::<T>::from(context)
            .get_code_hash(&address)
            .into()
    }

    unsafe extern "C" fn get_block_hash<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        number: i64,
    ) -> ffi::evmc_bytes32 {
        HostContextWrapper::<T>::from(context)
            .get_block_hash(number as u64)
            .into()
    }

    unsafe extern "C" fn selfdestruct<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
        beneficiary: *const ffi::evmc_address,
    ) {
        let address = Address::from(*address);
        let beneficiary = Address::from(*beneficiary);
        HostContextWrapper::<T>::from(context).selfdestruct(&address, &beneficiary);
    }

    unsafe extern "C" fn copy_code<T: HostContext>(
        context: *mut ffi::evmc_host_context,
        address: *const ffi::evmc_address,
        code_offset: usize,
        buffer_data: *mut u8,
        buffer_size: usize,
    ) -> usize {
        let address = Address::from(*address);
        let buffer: &[u8] = from_raw_parts(buffer_data, buffer_size);
        HostContextWrapper::<T>::from(context).copy_code(&address, code_offset, buffer)
    }

    ffi::evmc_host_interface {
        get_tx_context: Some(get_tx_context::<T>),
        account_exists: Some(account_exists::<T>),
        get_storage: Some(get_storage::<T>),
        set_storage: Some(set_storage::<T>),
        get_balance: Some(get_balance::<T>),
        selfdestruct: Some(selfdestruct::<T>),
        call: Some(call::<T>),
        emit_log: Some(emit_log::<T>),
        copy_code: Some(copy_code::<T>),
        get_code_size: Some(get_code_size::<T>),
        get_code_hash: Some(get_code_hash::<T>),
        get_block_hash: Some(get_block_hash::<T>),
    }
}
