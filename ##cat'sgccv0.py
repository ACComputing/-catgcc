import tkinter as tk
from tkinter import scrolledtext
import time

class AsmToCCompiler:
    """
    A compiler that translates a subset of assembly to C.
    Supports .data and .text sections with basic instructions,
    labels, and conditional/unconditional jumps.
    """

    def __init__(self):
        self.symbols = {}          # variable name -> info
        self.labels = {}           # label name -> line number (for validation)
        self.registers = {'EAX', 'EBX', 'ECX', 'EDX', 'AL', 'AH', 'BL', 'BH'}
        self.data_decls = []        # list of (name, type, value)
        self.text_insts = []        # list of (mnemonic, operands, lineno, label)
        self.errors = []
        self.warnings = []
        self.current_section = None

    def tokenize_line(self, line, lineno):
        """Convert a line of assembly into a list of tokens, stripping comments."""
        line = line.split(';')[0].strip()
        if not line:
            return None
        # Make commas and colons separate tokens
        line = line.replace(',', ' , ').replace(':', ' : ')
        tokens = line.split()
        return tokens

    def parse_line(self, tokens, lineno):
        """Parse a single line of tokens based on the current section."""
        if not tokens:
            return
        first = tokens[0]
        if first.startswith('.'):
            # Directive
            if first == '.data':
                self.current_section = 'data'
            elif first == '.text':
                self.current_section = 'text'
            else:
                self.error(f"Unknown directive '{first}'", lineno)
        else:
            if self.current_section == 'data':
                self.parse_data_line(tokens, lineno)
            elif self.current_section == 'text':
                self.parse_text_line(tokens, lineno)
            else:
                self.error("Instruction or data outside any section", lineno)

    def parse_data_line(self, tokens, lineno):
        """Parse a line in the .data section: name DB value  or  name DW value."""
        if len(tokens) < 3:
            self.error("Invalid data declaration", lineno)
            return
        name = tokens[0]
        if name in self.symbols:
            self.error(f"Duplicate symbol '{name}'", lineno)
            return
        typ = tokens[1].upper()
        if typ not in ('DB', 'DW'):
            self.error(f"Expected DB or DW, got '{typ}'", lineno)
            return
        value_token = tokens[2]
        try:
            value = int(value_token)
        except ValueError:
            self.error(f"Invalid number '{value_token}'", lineno)
            return
        self.symbols[name] = {'type': typ, 'value': value, 'lineno': lineno}
        self.data_decls.append((name, typ, value))

    def parse_text_line(self, tokens, lineno):
        """
        Parse a line in the .text section.
        Handles labels and instructions.
        """
        idx = 0
        label = None

        # Check for a label (identifier followed by ':')
        if len(tokens) >= 2 and tokens[1] == ':':
            label = tokens[0]
            if label in self.labels:
                self.error(f"Duplicate label '{label}'", lineno)
            else:
                self.labels[label] = lineno
            idx = 2   # skip label and colon

        if idx >= len(tokens):
            # Line with just a label, no instruction
            self.text_insts.append(('LABEL', [label], lineno, None))
            return

        mnemonic = tokens[idx].upper()
        # Collect operands, skipping commas
        operands = []
        i = idx + 1
        while i < len(tokens):
            tok = tokens[i]
            if tok == ',':
                i += 1
                continue
            operands.append(tok)
            i += 1

        # Validate mnemonic
        valid_mnemonics = {
            'MOV', 'ADD', 'SUB', 'INC', 'DEC', 'AND', 'OR', 'XOR',
            'CMP', 'JMP', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'
        }
        if mnemonic not in valid_mnemonics:
            self.error(f"Unsupported instruction '{mnemonic}'", lineno)
            return

        # Validate operand count based on mnemonic
        if mnemonic in ('MOV', 'ADD', 'SUB', 'AND', 'OR', 'XOR', 'CMP'):
            if len(operands) != 2:
                self.error(f"'{mnemonic}' requires 2 operands", lineno)
                return
        elif mnemonic in ('INC', 'DEC'):
            if len(operands) != 1:
                self.error(f"'{mnemonic}' requires 1 operand", lineno)
                return
        elif mnemonic in ('JMP', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'):
            if len(operands) != 1:
                self.error(f"'{mnemonic}' requires 1 operand (label)", lineno)
                return

        # Validate operands (basic type checks)
        if mnemonic in ('MOV', 'ADD', 'SUB', 'AND', 'OR', 'XOR', 'CMP'):
            dest = operands[0]
            src = operands[1]
            # Destination must be register or variable
            if dest.upper() not in self.registers and dest not in self.symbols:
                self.error(f"Invalid destination operand '{dest}'", lineno)
                return
            # Source can be register, variable, or immediate number
            src_upper = src.upper()
            if src_upper not in self.registers and src not in self.symbols:
                try:
                    int(src)
                except ValueError:
                    self.error(f"Invalid source operand '{src}'", lineno)
                    return
        elif mnemonic in ('INC', 'DEC'):
            dest = operands[0]
            if dest.upper() not in self.registers and dest not in self.symbols:
                self.error(f"Invalid operand '{dest}' for {mnemonic}", lineno)
                return
        elif mnemonic in ('JMP', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'):
            # Label will be validated later (may be forward reference)
            pass

        # Normalize register names to uppercase
        if mnemonic not in ('JMP', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'):
            # Only for instructions with register operands
            for i, op in enumerate(operands):
                if op.upper() in self.registers:
                    operands[i] = op.upper()

        self.text_insts.append((mnemonic, operands, lineno, label))

    def error(self, msg, lineno):
        self.errors.append(f"Line {lineno}: {msg}")

    def warn(self, msg, lineno):
        self.warnings.append(f"Line {lineno}: warning: {msg}")

    def compile(self, asm_text):
        """Main compilation routine: parse and generate C."""
        self.__init__()   # reset state
        lines = asm_text.split('\n')
        for i, line in enumerate(lines):
            tokens = self.tokenize_line(line, i+1)
            if tokens:
                self.parse_line(tokens, i+1)

        if self.errors:
            return None, self.errors, self.warnings

        # Check for undefined labels
        undefined = self.find_undefined_labels()
        if undefined:
            err_msg = "Undefined labels: " + ", ".join(undefined)
            return None, [err_msg], self.warnings

        c_code = self.generate_code()
        return c_code, self.errors, self.warnings

    def find_undefined_labels(self):
        """Check that all jump targets are defined."""
        defined = set(self.labels.keys())
        referenced = set()
        for mnemonic, operands, lineno, label in self.text_insts:
            if mnemonic in ('JMP', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'):
                referenced.add(operands[0])
        return referenced - defined

    def generate_code(self):
        """Generate C code from the parsed data and instructions."""
        out = []
        out.append("#include <stdio.h>")
        out.append("")
        out.append("int main() {")
        out.append("    /* Registers */")
        out.append("    int EAX = 0, EBX = 0, ECX = 0, EDX = 0;")
        out.append("    int AL = 0, AH = 0, BL = 0, BH = 0;  /* 8-bit parts (simulated as int) */")

        if self.data_decls:
            out.append("")
            out.append("    /* Data variables */")
            for name, typ, value in self.data_decls:
                c_type = "char" if typ == "DB" else "int"
                out.append(f"    {c_type} {name} = {value};")

        if self.text_insts:
            out.append("")
            out.append("    /* Instructions */")
            last_cmp = None  # track the last CMP operands

            for mnemonic, operands, lineno, label in self.text_insts:
                # Output label if present
                if label:
                    out.append(f"{label}: ;")

                if mnemonic == 'LABEL':
                    # Already handled above (label with no instruction)
                    continue

                # Handle instructions
                if mnemonic == 'MOV':
                    out.append(f"    {operands[0]} = {operands[1]};")
                elif mnemonic == 'ADD':
                    out.append(f"    {operands[0]} += {operands[1]};")
                elif mnemonic == 'SUB':
                    out.append(f"    {operands[0]} -= {operands[1]};")
                elif mnemonic == 'INC':
                    out.append(f"    {operands[0]}++;")
                elif mnemonic == 'DEC':
                    out.append(f"    {operands[0]}--;")
                elif mnemonic == 'AND':
                    out.append(f"    {operands[0]} &= {operands[1]};")
                elif mnemonic == 'OR':
                    out.append(f"    {operands[0]} |= {operands[1]};")
                elif mnemonic == 'XOR':
                    out.append(f"    {operands[0]} ^= {operands[1]};")
                elif mnemonic == 'CMP':
                    # Store operands for conditional jumps
                    last_cmp = (operands[0], operands[1])
                    # No output code for CMP itself
                elif mnemonic == 'JMP':
                    out.append(f"    goto {operands[0]};")
                elif mnemonic in ('JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'):
                    if last_cmp is None:
                        # No preceding CMP, use 0 as default (will likely misbehave)
                        left = right = "0"
                    else:
                        left, right = last_cmp
                    # Map to C operator
                    op_map = {
                        'JE': '==', 'JNE': '!=',
                        'JG': '>', 'JL': '<',
                        'JGE': '>=', 'JLE': '<='
                    }
                    c_op = op_map[mnemonic]
                    out.append(f"    if ({left} {c_op} {right}) goto {operands[0]};")
                else:
                    # Should not happen
                    out.append(f"    /* Unsupported instruction {mnemonic} */")

        out.append("")
        out.append("    return 0;")
        out.append("}")
        return "\n".join(out)


class CompilerGUI:
    def __init__(self, root):
        self.root = root
        root.title("CAT'S GCC 0.1")
        root.geometry("700x600")
        root.resizable(True, True)

        # Dark theme colors
        bg_color = "#000000"
        fg_color = "#0000FF"
        btn_bg = "#000000"
        btn_fg = "#0000FF"
        btn_active_bg = "#333333"
        btn_active_fg = "#6666FF"
        text_bg = "#000000"
        text_fg = "#0000FF"
        insert_color = "#0000FF"
        label_fg = "#0000FF"
        status_fg = "#8888FF"

        root.configure(bg=bg_color)

        # Top frame: input
        input_frame = tk.Frame(root, bg=bg_color)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tk.Label(input_frame, text="Assembly Input:", font=('Arial', 10, 'bold'),
                 bg=bg_color, fg=label_fg).pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(
            input_frame, height=8, font=("Courier", 10),
            bg=text_bg, fg=text_fg, insertbackground=insert_color
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Middle frame: compiler messages (like GCC output)
        msg_frame = tk.Frame(root, bg=bg_color)
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tk.Label(msg_frame, text="Compiler Output:", font=('Arial', 10, 'bold'),
                 bg=bg_color, fg=label_fg).pack(anchor=tk.W)
        self.msg_text = scrolledtext.ScrolledText(
            msg_frame, height=5, font=("Courier", 10),
            bg=text_bg, fg=text_fg, insertbackground=insert_color
        )
        self.msg_text.pack(fill=tk.BOTH, expand=True)

        # Bottom frame: generated C code
        output_frame = tk.Frame(root, bg=bg_color)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tk.Label(output_frame, text="Generated C Code:", font=('Arial', 10, 'bold'),
                 bg=bg_color, fg=label_fg).pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(
            output_frame, height=8, font=("Courier", 10),
            bg=text_bg, fg=text_fg, insertbackground=insert_color
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Control bar
        control_frame = tk.Frame(root, bg=bg_color)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.compile_btn = tk.Button(
            control_frame, text="Compile (gcc -o program)", 
            command=self.compile_action,
            bg=btn_bg, fg=btn_fg, activebackground=btn_active_bg, activeforeground=btn_active_fg,
            relief=tk.RAISED, bd=2, padx=10
        )
        self.compile_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = tk.Button(
            control_frame, text="Clear All", command=self.clear_all,
            bg=btn_bg, fg=btn_fg, activebackground=btn_active_bg, activeforeground=btn_active_fg,
            relief=tk.RAISED, bd=2, padx=10
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(
            control_frame, text="Ready", anchor=tk.W,
            bg=bg_color, fg=status_fg
        )
        self.status_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # Insert example
        self.insert_example()

    def insert_example(self):
        example = """; Example with conditional jump
.data
x DB 5
y DB 10
result DB 0
.text
start:
MOV al, x
CMP al, y
JG greater
MOV result, 0
JMP end
greater:
MOV result, 1
end:
"""
        self.input_text.insert(tk.END, example)

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.msg_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status_label.config(text="Cleared", fg="#8888FF")

    def compile_action(self):
        asm_code = self.input_text.get("1.0", tk.END).strip()
        if not asm_code:
            self.msg_text.insert(tk.END, "gcc: fatal error: no input files\n")
            self.status_label.config(text="Compilation failed", fg="red")
            return

        # Clear previous output
        self.msg_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

        # Simulate compilation command
        cmd = f"$ gcc -o program input.asm   # CAT'S GCC 0.1\n"
        self.msg_text.insert(tk.END, cmd)

        start_time = time.time()
        compiler = AsmToCCompiler()
        c_code, errors, warnings = compiler.compile(asm_code)
        elapsed = (time.time() - start_time) * 1000  # ms

        # Output messages
        if warnings:
            for w in warnings:
                self.msg_text.insert(tk.END, f"warning: {w}\n")
        if errors:
            for e in errors:
                self.msg_text.insert(tk.END, f"error: {e}\n")
            self.msg_text.insert(tk.END, f"compilation terminated.\n")
            self.status_label.config(text=f"Compilation failed ({elapsed:.1f} ms)", fg="red")
        else:
            self.msg_text.insert(tk.END, f"Compilation successful ({elapsed:.1f} ms)\n")
            self.output_text.insert(tk.END, c_code)
            self.status_label.config(text=f"Compilation finished ({elapsed:.1f} ms)", fg="#88FF88")

        # Scroll to end
        self.msg_text.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = CompilerGUI(root)
    root.mainloop()