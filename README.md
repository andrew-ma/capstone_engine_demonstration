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
* type in 'j{rowidx}' to try to jump to the jmp location (currently only works on rows that are in "jump" group and that have an address as operand so jmp rax won't work)
* type in 'b' if you have use 'j{rowidx}' and it will return you to previous address


### Note: Radare2, REMnux, and Cuckoo use Capstone