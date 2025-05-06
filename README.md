# 🧠 Nirvana Notject

A low-level memory editing tool written in Rust. This project provides a basic but powerful interface for reading and analyzing the memory of external processes on Windows systems.

## 🔍 Features

- Creates a `Memory` instance to interface with process memory.
- Scans and lists memory regions of a target process.
- Prints details of discovered regions (addresses and sizes).
- Demonstrates reading a value from the first readable region.
- Searches memory for a specific byte pattern (e.g., NOP instructions `0x90`).

## Disclaimer

This project is intended for educational and experimental purposes.

## License

[MIT](LICENSE)
