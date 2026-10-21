# evm-cbor-audit

evm-cbor-audit reads deployed EVM runtime bytecode through JSON-RPC and decodes the Solidity CBOR metadata trailer, so you can check the embedded compiler version and source-verification locator without an explorer API.

## Example

This is real output from Optimism mainnet for the WETH predeploy at `0x4200000000000000000000000000000000000006`.

    $ python bytecode_cbor.py --rpc-url https://mainnet.optimism.io --address 0x4200000000000000000000000000000000000006
    {
      "address": "0x4200000000000000000000000000000000000006",
      "block": "latest",
      "code_bytes": 2041,
      "compiler": "0.5.17",
      "metadata": {
        "bzzr1": "0x91c18790e0cca5011d2518024840ee00fecc67e11f56fd746f2cf84d5b583e00",
        "solc": "0x000511"
      },
      "metadata_length": 50,
      "metadata_start": 1989,
      "source": "rpc",
      "status": "ok"
    }

## Usage

Use a live contract:

    python bytecode_cbor.py --rpc-url RPC_URL --address CONTRACT [--block latest]

Use a saved bytecode string without a network request:

    python bytecode_cbor.py --bytecode 0x...

The command accepts a block tag such as `latest`, or a hex block number. A missing or malformed trailer is reported as JSON instead of being treated as a valid Solidity metadata record.

## How it works

The tool calls `eth_getCode`, reads the final two bytes as a big-endian CBOR length, and decodes the preceding definite-length CBOR item. It supports the map, array, integer, byte-string, text-string, tag, and simple values used by Solidity metadata. Byte strings are printed as hex, and a three-byte `solc` value is formatted as a compiler version.

## Tests

Run `python -m unittest -v`.
