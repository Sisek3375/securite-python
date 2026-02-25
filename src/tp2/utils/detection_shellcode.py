import capstone
import pylibemu
import re
from os import getenv
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
OPENAI_KEY = getenv("OPENAI_KEY")

class Disassembler:
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True

    def get_shellcode_strings(self) -> list[str]:
        """
        extract shellcode strings
        """
        pattern = re.compile(rb'[\x20-\x7e]{4,}')
        return [match.group().decode('ascii') for match in pattern.finditer(self.shellcode)]

    def get_capstone_analysis(self):
        """
        disassemble shellcode with capstone
        """
        instructions = []
        mnemonic_count = {}

        for insn in self.md.disasm(self.shellcode, 0x0):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex()
            })
            mnemonic_count[insn.mnemonic] = mnemonic_count.get(insn.mnemonic, 0) + 1

        top_mnemonics = sorted(mnemonic_count.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "total_instructions": len(instructions),
            "instructions": instructions,
            "top_mnemonics": top_mnemonics,
            "strings": self.get_shellcode_strings()
        }


class Emulator:
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.emu = pylibemu.Emulator

    def get_pylibemu_analysis(self) -> dict:
        """
        Emulate the shellcode with pylibemu
        """
        offset = self.emu.test(self.shellcode)

        if offset < 0:
            return {
                "shellcode_detected": False,
                "offset": None,
                "profile": None
            }

        return {
            "shellcode_detected": True,
            "offset": offset,
            "profile": self.emu.emu_profile_output
        }


class ShellcodeAnalyzer:
    def __init__(self, shellcode):
        self.shellcode = shellcode
        self.disassembler = Disassembler(shellcode)
        self.emulator = Emulator(shellcode)

    def get_llm_analysis(self) ->str:
        capstone_result = self.disassembler.get_capstone_analysis()

        client = OpenAI(api_key=OPENAI_KEY)
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": str(capstone_result)}]
        )
        return response.choices[0].message.content
