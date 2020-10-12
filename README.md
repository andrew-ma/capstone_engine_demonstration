# Capstone Engine Demo

## Install with pipenv
```
pipenv install
```

## Run
```
python -m pipenv shell
python demonstration.py -h
```

## CLI options
```
usage: demonstration.py [-h] [--offset OFFSET] [--pagesize PAGESIZE] [-lite] [-table] [--skipto SKIPTO] filename

positional arguments:
  filename             file to disassemble

optional arguments:
  -h, --help           show this help message and exit
  --offset OFFSET      offset for first instruction (for if address 0 in file corresponds to different address)
  --pagesize PAGESIZE  how many instructions to display per page
  -lite                lite mode to show only address, mnemonic, operands, and size of instruction
  -table               show in table format
  --skipto SKIPTO      skip to this address (usually should be address of .text section)h
```

## Usage
* type in address (integer '938' or hex '0x3AA') to go to that address
* type in 'q' to quit