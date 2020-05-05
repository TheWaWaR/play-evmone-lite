mod evmc;

use std::collections::HashMap;
use std::fmt;

use evmc::{
    get_interface, Address, Bytes32, CallKind, EvmcVm, ExecutionContext, ExecutionMessage,
    ExecutionResult, HostContext, HostContextPtr, HostContextWrapper, HostInterface, Revision,
    StatusCode, StorageStatus, TxContext, Uint256,
};
use evmc_sys as ffi;
use serde::{Deserialize, Serialize};

const CODE: &str = "60806040525b607b60006000508190909055505b610018565b60db806100266000396000f3fe60806040526004361060295760003560e01c806360fe47b114602f5780636d4ce63c14605b576029565b60006000fd5b60596004803603602081101560445760006000fd5b81019080803590602001909291905050506084565b005b34801560675760006000fd5b50606e6094565b6040518082815260200191505060405180910390f35b8060006000508190909055505b50565b6000600060005054905060a2565b9056fea26469706673582212204e58804e375d4a732a7b67cce8d8ffa904fa534d4555e655a433ce0a5e0d339f64736f6c63430006060033";
const INPUT: &str = "6d4ce63c";

#[link(name = "evmone")]
extern "C" {
    fn evmc_create_evmone() -> *mut ffi::evmc_vm;
}

fn main() -> Result<(), String> {
    let sender = Address([128u8; 20]);
    let value = Uint256([1u8; 32]);
    let create2_salt = Bytes32([0u8; 32]);
    let destination = Address::default();

    let vm = EvmcVm::new(unsafe { evmc_create_evmone() });

    let context_string = {
        println!(">>> Create Contract");
        let code = hex::decode(CODE).unwrap();
        let input_data = b"";
        let host_context = TestHostContext::new(0, destination.clone());
        let host_context_ptr = HostContextPtr::from(Box::new(host_context));
        let mut context =
            ExecutionContext::new(TestHostContext::interface(), host_context_ptr.ptr);
        println!("code: {}", hex::encode(&code));
        println!("input-data: {}", hex::encode(&input_data));
        // static
        let flags = 0;
        let raw_message = ffi::evmc_message {
            kind: CallKind::EVMC_CREATE,
            flags,
            depth: 0,
            gas: 4_466_666,
            destination: destination.clone().into(),
            sender: sender.clone().into(),
            input_data: input_data.as_ptr(),
            input_size: input_data.len(),
            value: value.clone().into(),
            create2_salt: create2_salt.into(),
        };
        let message = ExecutionMessage::from(&raw_message);
        let result = vm.execute(Revision::EVMC_PETERSBURG, &code, &message, &mut context);
        println!("Execution result: {:#?}\n", result);

        assert_eq!(result.create_address, Address::default());
        let mut wrapper = HostContextWrapper::from(context.context);
        let context: &mut TestHostContext = &mut wrapper;
        if result.status_code == StatusCode::EVMC_SUCCESS
            && (message.kind == CallKind::EVMC_CREATE || message.kind == CallKind::EVMC_CREATE2)
        {
            context.update_code(destination.clone(), result.output_data);
        }
        let context_string = serde_json::to_string_pretty(context).unwrap();
        println!("Context: {}\n", context_string);
        context_string
    };

    let input_data = hex::decode(INPUT).unwrap();
    let host_context: TestHostContext = serde_json::from_str(&context_string).unwrap();
    let code = host_context.accounts.get(&destination).unwrap().code.clone().unwrap().0;
    println!(">>> Call SimpleStorage::get()");
    println!("code: {}", hex::encode(&code));
    println!("input-data: {}", hex::encode(&input_data));
    // static
    let flags = 1;
    let raw_message = ffi::evmc_message {
        kind: CallKind::EVMC_CALL,
        flags,
        depth: 0,
        gas: 4_466_666,
        destination: destination.into(),
        sender: sender.into(),
        input_data: input_data.as_ptr(),
        input_size: input_data.len(),
        value: value.into(),
        create2_salt: Default::default(),
    };
    let message = ExecutionMessage::from(&raw_message);
    let host_context_ptr = HostContextPtr::from(Box::new(host_context));
    let mut context =
        ExecutionContext::new(TestHostContext::interface(), host_context_ptr.ptr);
    let result = vm.execute(Revision::EVMC_PETERSBURG, &code, &message, &mut context);
    println!("Execution result: {:#?}\n", result);
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct JsonBytes(pub Vec<u8>);

fn parse_bytes(bytes: &[u8]) -> Result<JsonBytes, String> {
    let mut target = vec![0u8; bytes.len() / 2];
    hex::decode_to_slice(bytes, &mut target).map_err(|e| e.to_string())?;
    Ok(JsonBytes(target))
}
impl_serde!(JsonBytes, BytesVisitor, parse_bytes);

impl fmt::Debug for JsonBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default, Deserialize, Serialize)]
pub struct Value {
    data: Bytes32,
    // Modify time:
    //   0 => first set
    //   1 => modified
    //   2..n => modifled again
    modify_time: usize,
}

impl Value {
    fn new(data: Bytes32) -> Value {
        Value {
            data,
            modify_time: 0,
        }
    }

    fn update_data(&mut self, data: Bytes32) -> bool {
        if data != self.data {
            self.data = data;
            self.modify_time += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct LogEntry {
    data: JsonBytes,
    topics: Vec<Bytes32>,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct AccountData {
    nonce: u64,
    address: Address,
    // The code stored in the account, not the code created the account
    code: Option<JsonBytes>,
    storage: HashMap<Bytes32, Value>,
    logs: Vec<LogEntry>,
}

impl AccountData {
    pub fn new(address: Address) -> AccountData {
        println!("AccountData::new({:?})", address);
        AccountData {
            nonce: 0,
            address,
            code: None,
            storage: HashMap::default(),
            logs: Vec::new(),
        }
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct TestHostContext {
    pub depth: u32,
    // Current account's address
    pub current_account: Address,
    pub accounts: HashMap<Address, AccountData>,
    pub destructed_accounts: Vec<Address>,
}

impl TestHostContext {
    pub fn new(depth: u32, current_account: Address) -> TestHostContext {
        TestHostContext {
            depth,
            current_account,
            accounts: HashMap::default(),
            destructed_accounts: Vec::new(),
        }
    }

    pub fn contract_exists(&self, address: &Address) -> bool {
        self.accounts
            .get(address)
            .map(|account| account.code.is_some())
            .unwrap_or(false)
    }

    pub fn update_code(&mut self, address: Address, code: Vec<u8>) {
        // println!(">> before update_code context: {:#?}", self);
        let account = self
            .accounts
            .entry(address.clone())
            .or_insert_with(|| AccountData::new(address));
        account.code = Some(JsonBytes(code));
        // println!(">> after update_code context: {:#?}", self);
    }

    // We assume the `other` account always have latest state
    pub fn update(&mut self, other: &TestHostContext) {
        if other.destructed_accounts.len() < self.destructed_accounts.len() {
            panic!(
                "other destructed_accounts length invalid ({} < {})",
                other.destructed_accounts.len(),
                self.destructed_accounts.len()
            );
        }
        for address in &other.destructed_accounts {
            if other.accounts.contains_key(address) {
                panic!(
                    "Invalid state for context, address={:?}",
                    other.current_account
                );
            }
        }

        self.accounts = other.accounts.clone();
        self.destructed_accounts = other.destructed_accounts.clone();
    }
}

impl HostContext for TestHostContext {
    fn interface() -> HostInterface {
        get_interface::<TestHostContext>()
    }

    fn get_tx_context(&mut self) -> TxContext {
        TxContext {
            tx_gas_price: Uint256::default().into(),
            tx_origin: Address([128u8; 20]).into(),
            block_coinbase: Address::default().into(),
            block_number: 0,
            block_timestamp: 0,
            block_gas_limit: 666_666_666,
            block_difficulty: Uint256::default().into(),
            chain_id: Uint256::default().into(),
        }
    }

    fn account_exists(&mut self, address: &Address) -> bool {
        println!("account_exists(address: {:?})", address);
        true
    }

    fn get_storage(&mut self, address: &Address, key: &Bytes32) -> Bytes32 {
        println!("get(address: {:?}, key: {:?})", address, key);
        self.accounts
            .get(address)
            .and_then(|account| account.storage.get(key))
            .map(|value| value.data.clone())
            .unwrap_or_default()
    }

    fn set_storage(&mut self, address: Address, key: Bytes32, value: Bytes32) -> StorageStatus {
        // println!(">> before set_storage context: {:#?}", self);
        println!(
            "set(address: {:?}, key: {:?}), value: {:?}, contains_address: {}",
            address,
            key,
            value,
            self.accounts.contains_key(&address)
        );
        let (modify_time, changed) = {
            let val = self
                .accounts
                .entry(address.clone())
                .or_insert_with(|| AccountData::new(address))
                .storage
                .entry(key)
                .or_insert_with(|| Value::new(value.clone()));
            let changed = val.update_data(value);
            (val.modify_time, changed)
        };
        // println!(">> after set_storage context: {:#?}", self);

        match (modify_time, changed) {
            (0, true) => panic!("Invalid storage value data"),
            (0, false) => StorageStatus::EVMC_STORAGE_ADDED,
            (1, true) => StorageStatus::EVMC_STORAGE_MODIFIED,
            (_, true) => StorageStatus::EVMC_STORAGE_MODIFIED_AGAIN,
            (_, false) => StorageStatus::EVMC_STORAGE_UNCHANGED,
        }
    }

    fn get_balance(&mut self, address: &Address) -> Uint256 {
        println!("get_balance(address: {:?})", address);
        Uint256::default()
    }

    fn call(&mut self, message: ExecutionMessage) -> ExecutionResult {
        println!("call(message: {:?})", message);
        let destination = Address::from(message.destination);
        let code = if let Some(account) = self.accounts.get(&destination) {
            if let Some(code) = account.code.as_ref() {
                code.clone()
            } else {
                panic!("No code found form account: {:?}", destination);
            }
        } else {
            panic!("Not such account: {:?}", destination);
        };
        let host_context = {
            let mut context = self.clone();
            context.depth = message.depth as u32 + 1;
            context.current_account = destination.clone();
            Box::new(context)
        };
        let host_context_ptr = HostContextPtr::from(host_context);
        let mut context = ExecutionContext::new(TestHostContext::interface(), host_context_ptr.ptr);
        let vm = EvmcVm::new(unsafe { evmc_create_evmone() });
        let result = vm.execute(Revision::EVMC_PETERSBURG, &code.0, &message, &mut context);

        let mut wrapper = HostContextWrapper::from(context.context);
        let context: &mut TestHostContext = &mut wrapper;
        if result.status_code == StatusCode::EVMC_SUCCESS {
            assert_eq!(result.create_address, destination);
            if message.kind == CallKind::EVMC_CREATE || message.kind == CallKind::EVMC_CREATE2 {
                context.update_code(destination, result.output_data.clone());
            }
        }
        self.update(context);
        result
    }

    fn selfdestruct(&mut self, address: &Address, beneficiary: &Address) {
        self.destructed_accounts.push(address.clone());
        println!(
            "emit_log(address: {:?}, beneficiary: {:?})",
            address, beneficiary
        );
    }

    fn emit_log(&mut self, address: &Address, data: &[u8], topics: &[Bytes32]) {
        println!(
            "emit_log(address: {:?}, data: {}, topics: {:?})",
            address,
            hex::encode(data),
            topics
        );
        self.accounts
            .entry(address.clone())
            .or_insert_with(|| AccountData::new(address.clone()))
            .logs
            .push(LogEntry {
                data: JsonBytes(data.to_vec()),
                topics: topics.to_vec(),
            });
    }

    fn copy_code(&mut self, address: &Address, code_offset: usize, buffer: &[u8]) -> usize {
        println!(
            "copy_code(address: {:?}, code_offset: {:?}, buffer: {})",
            address,
            code_offset,
            hex::encode(buffer)
        );
        0
    }

    fn get_code_size(&mut self, address: &Address) -> usize {
        println!("get_code_size(address: {:?})", address);
        0
    }

    fn get_code_hash(&mut self, address: &Address) -> Bytes32 {
        println!("get_code_hash(address: {:?})", address);
        Bytes32::default()
    }

    fn get_block_hash(&mut self, number: u64) -> Bytes32 {
        println!("get_block_hash(number: {:?})", number);
        Bytes32::default()
    }
}
