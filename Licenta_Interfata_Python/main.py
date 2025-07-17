import serial
import serial.tools.list_ports
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
from PIL import Image, ImageTk
from Crypto.Cipher import AES




def read_bytes(ser, n):
    data = b""
    while len(data) < n:
        chunk = ser.read(n - len(data))
        if not chunk:
            raise RuntimeError("Timeout or connection lost")
        data += chunk
    return data


def format_bytes(data):
    return "".join(f"{b:02x}" for b in data)


class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-128 Interface")
        self.root.geometry("800x600")

        self.mode_var = tk.StringVar(value="Light")
        theme_menu = ttk.OptionMenu(root, self.mode_var,
                                    "Light", "Light", "Dark",
                                    command=self.switch_theme)
        theme_menu.grid(row=0, column=0, sticky="nw",
                        padx=10, pady=10)

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=1, column=0, sticky="nsew")
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.sigla1 = ImageTk.PhotoImage(
            Image.open("sigla1.png").resize((100, 100), Image.Resampling.LANCZOS))
        self.left_logo = ttk.Label(main_frame, image=self.sigla1)
        self.left_logo.grid(row=0, column=0, rowspan=2,
                            padx=(0, 10), pady=10, sticky="n")

        self.sigla2 = ImageTk.PhotoImage(
            Image.open("sigla2.png").resize((150, 100), Image.Resampling.LANCZOS))
        self.right_logo = ttk.Label(main_frame, image=self.sigla2)
        self.right_logo.grid(row=0, column=2, rowspan=2,
                             padx=(10, 0), pady=10, sticky="n")

        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=0, column=1, sticky="ew")


        ttk.Label(input_frame, text="Serial port:")\
            .grid(row=0, column=0, sticky="w", pady=5)
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_cb = ttk.Combobox(input_frame, values=ports,
                                    width=28, state="readonly")
        self.port_cb.grid(row=0, column=1, sticky="w", pady=5)
        if ports:
            self.port_cb.set(ports[0])
        ttk.Button(input_frame, text="Refresh",
                   command=self.refresh_ports)\
            .grid(row=0, column=2, padx=(5,0), pady=5)


        ttk.Label(input_frame, text="Mode:")\
            .grid(row=1, column=0, sticky="w", pady=5)
        self.mode_var_radio = tk.StringVar(value="0")
        ttk.Radiobutton(input_frame,
                        text="Encryption process (0)",
                        value="0",
                        variable=self.mode_var_radio,
                        command=self.update_text_label)\
            .grid(row=1, column=1, sticky="w")
        ttk.Radiobutton(input_frame,
                        text="Decryption process (1)",
                        value="1",
                        variable=self.mode_var_radio,
                        command=self.update_text_label)\
            .grid(row=1, column=2, sticky="w")

        ttk.Label(input_frame, text="Key (32 hex):")\
            .grid(row=2, column=0, sticky="w", pady=5)
        self.key_entry = ttk.Entry(input_frame, width=50)
        self.key_entry.grid(row=2, column=1,
                            columnspan=2, sticky="w", pady=5)

        self.text_label = tk.StringVar(value="Plaintext (32 hex):")
        ttk.Label(input_frame, textvariable=self.text_label)\
            .grid(row=3, column=0, sticky="w", pady=5)
        self.text_entry = ttk.Entry(input_frame, width=50)
        self.text_entry.grid(row=3, column=1,
                             columnspan=2, sticky="w", pady=5)

        ttk.Button(input_frame, text="Send",
                   command=self.send_data)\
            .grid(row=4, column=1, pady=10)

        self.output_text = scrolledtext.ScrolledText(
            main_frame, width=60, height=20, wrap=tk.WORD)
        self.output_text.grid(row=1, column=1, padx=10,
                              pady=10, sticky="nsew")
        main_frame.grid_columnconfigure(1, weight=1)

        self.set_light_theme()


    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_cb['values'] = ports
        if ports:
            self.port_cb.set(ports[0])



    def set_light_theme(self):
        style = ttk.Style()
        self.root.configure(bg="#ffffff")
        style.configure("TFrame", background="#ffffff")
        style.configure("TLabel", background="#ffffff",
                        foreground="#000000")
        style.configure("TRadiobutton", background="#ffffff",
                        foreground="#000000")
        style.configure("TButton", background="#e0e0e0",
                        foreground="#000000")
        style.configure("TEntry", fieldbackground="#ffffff",
                        foreground="#000000")
        self.output_text.configure(bg="#ffffff", fg="#000000")



    def set_dark_theme(self):
        style = ttk.Style()
        self.root.configure(bg="#333333")
        style.configure("TFrame", background="#333333")
        style.configure("TLabel", background="#333333",
                        foreground="#ffffff")
        style.configure("TRadiobutton", background="#333333",
                        foreground="#ffffff")
        style.configure("TButton", background="#555555",
                        foreground="#ffffff")
        style.configure("TEntry", fieldbackground="#cccccc",
                        foreground="#000000")

        self.output_text.configure(bg="#cccccc", fg="#000000")


    def switch_theme(self, mode):
        if mode == "Dark":
            self.set_dark_theme()
        else:
            self.set_light_theme()


    def update_text_label(self):
        self.text_label.set(
            "Ciphertext (32 hex):"
            if self.mode_var_radio.get() == "1"
            else "Plaintext"
        )


    def read_and_filter(self, ser, field_name,
                        round_num, prev_value):
        data = read_bytes(ser, 16)
        while data == b'\x00'*16 or data == prev_value:
            data = read_bytes(ser, 16)
        self.output_text.insert(
            tk.END,
            f"round[{round_num:2}]."
            f"{field_name:<8} {format_bytes(data)}\n"
        )
        self.output_text.see(tk.END)
        self.root.update()
        return data

    def send_data(self):
        self.output_text.delete(1.0, tk.END)
        start_time = time.time()

        port = self.port_cb.get().strip()
        mode = self.mode_var_radio.get()
        key_hex = self.key_entry.get().strip().lower()
        text_hex = self.text_entry.get().strip().lower()

        if not port:
            self.output_text.insert(
                tk.END, "Eroare: Selecteaza un port serial.\n")
            return
        if mode not in ['0','1']:
            self.output_text.insert(
                tk.END, "Eroare: Modul invalid! Foloseste 0 sau 1.\n")
            return
        if len(key_hex)!=32 or len(text_hex)!=32:
            self.output_text.insert(
                tk.END,
                "Eroare: Cheia si textul trebuie sa aiba "
                "exact 32 caractere hex.\n"
            )
            return

        try:
            key_bytes = bytes.fromhex(key_hex)
            text_bytes = bytes.fromhex(text_hex)
            mode_byte = bytes([int(mode)])
        except ValueError:
            self.output_text.insert(
                tk.END,
                "Eroare: Intrari hex invalide.\n"
            )
            return

        prev_value = None

        try:
            with serial.Serial(port, 9600,
                               timeout=5) as ser:
                self.output_text.insert(
                    tk.END,
                    f"Trimite modul "
                    f"({'criptare' if mode=='0' else 'decriptare'}), "
                    f"cheia și "
                    f"{'plaintext-ul' if mode=='0' else 'ciphertext-ul'} "
                    f"către FPGA...\n"
                )
                ser.write(mode_byte + key_bytes + text_bytes)
                time.sleep(0.1)

                if mode=='0':
                    prev_value = self.read_and_filter(
                        ser, "k_sch", 0, prev_value
                    )
                    for r in range(1,11):
                        stages = (["start","s_box","s_row",
                                   "m_col","k_sch"]
                                  if r<10 else
                                  ["start","s_box","s_row",
                                   "k_sch","output"])
                        for st in stages:
                            prev_value = self.read_and_filter(
                                ser, st, r, prev_value
                            )
                else:
                    prev_value = self.read_and_filter(
                        ser, "ik_sch", 0, prev_value
                    )
                    for r in range(1,11):
                        stages = (["istart","is_row","is_box",
                                   "ik_sch","ik_add"]
                                  if r<10 else
                                  ["istart","is_row","is_box",
                                   "ik_sch","output"])
                        for st in stages:
                            prev_value = self.read_and_filter(
                                ser, st, r, prev_value
                            )

                self.output_text.insert(
                    tk.END, "\nProces finalizat.\n"
                )
                exec_time = time.time() - start_time
                self.output_text.insert(
                    tk.END,
                    f"Timp de executie: {exec_time:.3f} secunde\n"
                )
                self.output_text.see(tk.END)



            cipher = AES.new(key_bytes, AES.MODE_ECB)

            if mode=='0':
                expected = cipher.encrypt(text_bytes)
            else:
                expected = cipher.decrypt(text_bytes)

            if prev_value == expected:
                self.output_text.insert(tk.END, "TEST PASSED: Output corect.\n")
            else:
                self.output_text.insert(
                    tk.END,
                    f"TEST FAILED:\n"
                    f"  Expected: {expected.hex()}\n"
                    f"  Got:      {format_bytes(prev_value)}\n"
                )
            self.output_text.see(tk.END)


        except Exception as e:
            self.output_text.insert(
                tk.END, f"Eroare: {e}\n"
            )
            self.output_text.see(tk.END)


if __name__=="__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
