import os
import sys
import json
import threading
import time
import base64

import tkinter as tk
from tkinter import ttk, messagebox
from web3 import Web3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Constants
SERENDALE_CONTRACT_ADDRESS = "0x453b8D7fe1dbdA3496917055B7FB154432D83d76"
CRYSTALVALE_CONTRACT_ADDRESS = "0x4297531f246C5DaF65726F44889B960FaEf81ECE"
GAS_LIMITS = {
    "CV": 24000000,  # 24 million gas limit for Crystalvale
    "SD": 15000000,  # 15 million gas limit for Serendale
}

# Mappings
TYPE_MAPPING = {"solo": 1, "pack": 5, "squad": 3, "warr": 9}
BACKGROUND_MAPPING = {
    "desert": 0,
    "forest": 2,
    "plains": 4,
    "island": 6,
    "swamp": 8,
    "mountains": 10,
    "city": 12,
    "arctic": 14,
}
STAT_MAPPING = {
    "strength": 0,
    "agility": 2,
    "intelligence": 4,
    "wisdom": 6,
    "luck": 8,
    "vitality": 10,
    "endurance": 12,
    "dexterity": 14,
}


# Utility functions
def load_abi(file_name, logger):
    try:
        script_dir = os.getcwd()
        abi_file_path = os.path.join(script_dir, file_name)
        with open(abi_file_path, "r") as abi_file:
            return json.load(abi_file)
    except (IOError, json.JSONDecodeError) as e:
        logger(f"Error loading ABI: {e}")
        return None


def get_web3_instance(rpc_address, logger):
    w3 = Web3(Web3.HTTPProvider(rpc_address))
    if not w3.is_connected():
        logger(f"Failed to connect to RPC at {rpc_address}")
        return None
    return w3


def get_contract(w3, contract_address, abi):
    contract_address = Web3.to_checksum_address(contract_address)
    return w3.eth.contract(contract_address, abi=abi)


def map_value(attr, value, reverse=False):
    mappings = {
        "type": TYPE_MAPPING,
        "background": BACKGROUND_MAPPING,
        "stat": STAT_MAPPING,
    }
    mapping = mappings.get(attr, {})
    if reverse:
        return next((k for k, v in mapping.items() if v == value), None)
    return mapping.get(value, None)


def estimate_gas_for_complete_duel(contract, duel_id):
    try:
        gas_estimate = contract.functions.completeDuel(duel_id).estimate_gas()
        return gas_estimate
    except Exception as e:
        print(f"Error estimating gas for completing duel: {e}")
        return None


def calculate_max_duels_per_tx(contract, duel_id, realm):
    gas_limit_per_tx = GAS_LIMITS.get(
        realm, 15000000
    )  # Default to 15 million if realm not found
    gas_estimate = estimate_gas_for_complete_duel(contract, duel_id)
    if gas_estimate:
        max_duels = gas_limit_per_tx // gas_estimate
        return max_duels
    else:
        print("Could not estimate gas for completeDuel")
        return 0


class DuelContract:
    def __init__(self, rpc_address, contract_address, abi, logger):
        self.logger = logger
        self.w3 = get_web3_instance(rpc_address, self.logger)
        if not self.w3:
            return
        self.contract = get_contract(self.w3, contract_address, abi)

    def get_current_class_bonuses(self):
        try:
            return self.contract.functions.getCurrentClassBonuses().call()
        except Exception as e:
            self.logger(f"Error fetching current class bonuses: {e}")
            return None

    def get_player_duel_entries(self, address):
        try:
            return self.contract.functions.getPlayerDuelEntries(address).call()
        except Exception as e:
            self.logger(f"Error fetching player duel entries: {e}")
            return None

    def get_win_streak(self, address, duel_type):
        try:
            return self.contract.functions.getWinStreaks(address, duel_type).call()
        except Exception as e:
            self.logger(f"Error fetching win streak: {e}")
            return None

    def get_active_duels(self, address):
        try:
            contract_entry = self.contract.functions.getActiveDuels(
                Web3.to_checksum_address(address)
            ).call()
            duels = []
            for item in contract_entry:
                if item[0] == 0:
                    continue
                duels.append(
                    {
                        "id": item[0],
                        "player1": str(item[1]),
                        "player2": str(item[2]),
                        "player1DuelEntry": item[3],
                        "player2DuelEntry": item[4],
                        "winner": str(item[5]),
                        "player1Heroes": item[6],
                        "player2Heroes": item[7],
                        "startBlock": item[8],
                        "duelType": item[9],
                        "status": item[10],
                    }
                )
            return duels
        except Exception as e:
            self.logger(f"Error fetching active duels: {e}")
            return None

    def send_transaction(self, tx, private_key, tx_timeout_seconds):
        try:
            signed_tx = self.w3.eth.account.sign_transaction(
                tx, private_key=private_key
            )
            ret = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            self.logger("Transaction successfully sent!")
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(
                transaction_hash=signed_tx.hash,
                timeout=tx_timeout_seconds,
                poll_latency=2,
            )
            self.logger("Transaction mined!")
            return tx_receipt
        except Exception as e:
            self.logger(f"Transaction error: {e}")
            return None

    def enter_duel_lobby(
        self,
        duel_type,
        hero_ids,
        jewel_fee,
        background,
        stat,
        entries,
        private_key,
        nonce,
        gas_price_gwei,
        tx_timeout_seconds,
    ):
        try:
            account = self.w3.eth.account.from_key(private_key)
            self.w3.eth.default_account = account.address
            jewel_fee_wei = self.w3.to_wei(jewel_fee, "ether")
            tx = self.contract.functions.enterDuelLobby(
                duel_type, hero_ids, jewel_fee_wei, background, stat, entries
            ).build_transaction(
                {
                    "nonce": nonce,
                    **(
                        {
                            "maxFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxFeePerGas"], "gwei"
                            ),
                            "maxPriorityFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxPriorityFeePerGas"], "gwei"
                            ),
                        }
                        if isinstance(gas_price_gwei, dict)
                        else {"gasPrice": self.w3.to_wei(gas_price_gwei, "gwei")}
                    ),
                }
            )
            return self.send_transaction(tx, private_key, tx_timeout_seconds)
        except Exception as e:
            self.logger(f"Error entering duel lobby: {e}")
            return None

    def complete_duel(
        self, duel_id, private_key, nonce, gas_price_gwei, tx_timeout_seconds
    ):
        try:
            account = self.w3.eth.account.from_key(private_key)
            self.w3.eth.default_account = account.address
            tx = self.contract.functions.completeDuel(duel_id).build_transaction(
                {
                    "nonce": nonce,
                    **(
                        {
                            "maxFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxFeePerGas"], "gwei"
                            ),
                            "maxPriorityFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxPriorityFeePerGas"], "gwei"
                            ),
                        }
                        if isinstance(gas_price_gwei, dict)
                        else {"gasPrice": self.w3.to_wei(gas_price_gwei, "gwei")}
                    ),
                }
            )
            return self.send_transaction(tx, private_key, tx_timeout_seconds)
        except Exception as e:
            self.logger(f"Error completing duel: {e}")
            return None

    def complete_multiple_duels(
        self, num_to_complete, private_key, nonce, gas_price_gwei, tx_timeout_seconds
    ):
        try:
            account = self.w3.eth.account.from_key(private_key)
            self.w3.eth.default_account = account.address
            tx = self.contract.functions.completeDuels(
                num_to_complete
            ).build_transaction(
                {
                    "nonce": nonce,
                    **(
                        {
                            "maxFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxFeePerGas"], "gwei"
                            ),
                            "maxPriorityFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxPriorityFeePerGas"], "gwei"
                            ),
                        }
                        if isinstance(gas_price_gwei, dict)
                        else {"gasPrice": self.w3.to_wei(gas_price_gwei, "gwei")}
                    ),
                }
            )
            return self.send_transaction(tx, private_key, tx_timeout_seconds)
        except Exception as e:
            error_message = str(e)
            if "nonce too low" in error_message:
                self.logger("Nonce too low, incrementing nonce.")
                nonce += 1
            else:
                self.logger(f"Transaction error: {str(e)}")
                return None

    def matchmake(self, private_key, nonce, gas_price_gwei, tx_timeout_seconds):
        try:
            account = self.w3.eth.account.from_key(private_key)
            self.w3.eth.default_account = account.address
            tx = self.contract.functions.matchMake().build_transaction(
                {
                    "nonce": nonce,
                    **(
                        {
                            "maxFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxFeePerGas"], "gwei"
                            ),
                            "maxPriorityFeePerGas": self.w3.to_wei(
                                gas_price_gwei["maxPriorityFeePerGas"], "gwei"
                            ),
                        }
                        if isinstance(gas_price_gwei, dict)
                        else {"gasPrice": self.w3.to_wei(gas_price_gwei, "gwei")}
                    ),
                }
            )
            return self.send_transaction(tx, private_key, tx_timeout_seconds)
        except Exception as e:
            self.logger(f"Error matchmaking: {e}")
            return None

    def get_hero_duel_count_for_day(self, heroid, dueltype):
        try:
            return self.contract.functions.getHeroDuelCountForDay(
                heroid, dueltype
            ).call()
        except Exception as e:
            self.logger(f"Error fetching hero duel count: {e}")
            return None

    def get_player_score(self, address, duel_type):
        try:
            return self.contract.functions.getPlayerScore(
                Web3.to_checksum_address(address), duel_type
            ).call()
        except Exception as e:
            self.logger(f"Error fetching player score: {e}")
            return None


class DuelApp:
    CONFIG_FILE = "duel_config.json"

    def __init__(self, master):
        self.master = master
        self.master.title("Duel App")
        self.master.configure(bg="black")
        self.master.geometry("1000x880")

        self.pause_event = threading.Event()
        self.pause_event.set()  # Start in the unpaused state
        self.duel_task = None
        self.duel_queue = []  # Queue to store team settings

        self.duel_type_selection = tk.IntVar()
        self.stat_selections = set()
        self.background_selections = set()
        self.hero_id_fields = []
        self.current_realm = None
        self.private_key = None
        self.max_fee_per_gas_entry = tk.StringVar()
        self.priority_fee_per_gas_entry = tk.StringVar()

        self.stat_buttons = {}
        self.background_buttons = {}

        self.duel_settings = {}

        self.create_layout()
        self.create_input_frame()
        self.create_output_frame()
        self.load_config(self.CONFIG_FILE)
        self.apply_config()
        self.configure_styles()

        self.class_names = {
            0: "Warrior",
            1: "Knight",
            2: "Thief",
            3: "Archer",
            4: "Priest",
            5: "Wizard",
            6: "Monk",
            7: "Pirate",
            8: "Berserker",
            9: "Seer",
            10: "Legionnaire",
            11: "Scholar",
            16: "Paladin",
            17: "DarkKnight",
            18: "Summoner",
            19: "Ninja",
            20: "Shapeshifter",
            21: "Bard",
            24: "Dragoon",
            25: "Sage",
            26: "Spellbow",
            28: "DreadKnight",
        }

        self.gas_settings = {
            "CV": {"maxFeePerGas": 26, "maxPriorityFeePerGas": 0},
            "SD": {"maxFeePerGas": 26, "maxPriorityFeePerGas": 0},
        }

        self.duel_contract = None

        abi = load_abi("duel_abi.json", self.async_log_to_ui)
        if abi:
            rpc_server = "https://subnets.avax.network/defi-kingdoms/dfk-chain/rpc"  # Using one of the RPC addresses
            duel_contract_address = CRYSTALVALE_CONTRACT_ADDRESS
            self.duel_contract = DuelContract(
                rpc_server, duel_contract_address, abi, self.async_log_to_ui
            )
            if self.duel_contract.contract:
                self.update_class_bonuses()

    def create_gas_settings(self, master):
        ttk.Label(master, text="Max Gas").grid(row=24, column=0, sticky="w")
        max_fee_entry = ttk.Entry(
            master, width=10, textvariable=self.max_fee_per_gas_entry
        )
        max_fee_entry.grid(row=24, column=1, sticky="w")
        self.max_fee_per_gas_entry.set("26")  # Set default value

        ttk.Label(master, text="Priority Fee").grid(row=24, column=2, sticky="w")
        priority_fee_entry = ttk.Entry(
            master, width=10, textvariable=self.priority_fee_per_gas_entry
        )
        priority_fee_entry.grid(row=24, column=3, sticky="w")
        self.priority_fee_per_gas_entry.set("0")  # Set default value

    def log_to_ui(self, message, tag=None):
        self.master.after(0, lambda: self._log_to_ui(message, tag))

    def _log_to_ui(self, message, tag=None):
        if tag:
            self.log_output.insert(tk.END, message, tag)
        else:
            self.log_output.insert(tk.END, message)
        self.log_output.insert(tk.END, "\n")
        self.log_output.see(tk.END)

    def async_log_to_ui(self, message):
        threading.Thread(target=self.log_to_ui, args=(message,)).start()

    def configure_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="black")
        style.configure(
            "TButton",
            background="black",
            foreground="white",
            borderwidth=1,
            focuscolor="none",
        )
        style.configure("TLabel", background="black", foreground="white")
        style.map(
            "TButton",
            background=[("active", "grey"), ("!disabled", "black")],
            foreground=[("active", "white")],
        )
        style.configure(
            "TRadiobutton",
            background="black",
            foreground="white",
            indicatorbackground="black",
            indicatoron=False,
        )
        self.log_output.tag_config("common", foreground="white")
        self.log_output.tag_config("uncommon", foreground="lightgreen")
        self.log_output.tag_config("rare", foreground="blue")
        self.log_output.tag_config("legendary", foreground="orange")
        self.log_output.tag_config("mythic", foreground="purple")

    def get_rank_and_tag(self, rank):
        if rank < 30:
            return "Common I", "common"
        elif rank < 90:
            return "Common II", "common"
        elif rank < 150:
            return "Common III", "common"
        elif rank < 300:
            return "Uncommon I", "uncommon"
        elif rank < 500:
            return "Uncommon II", "uncommon"
        elif rank < 750:
            return "Uncommon III", "uncommon"
        elif rank < 1250:
            return "Rare I", "rare"
        elif rank < 2000:
            return "Rare II", "rare"
        elif rank < 3000:
            return "Rare III", "rare"
        elif rank < 4500:
            return "Legendary I", "legendary"
        elif rank < 7000:
            return "Legendary II", "legendary"
        elif rank < 11000:
            return "Legendary III", "legendary"
        elif rank < 16000:
            return "Mythic I", "mythic"
        elif rank < 22000:
            return "Mythic II", "mythic"
        else:
            return "Mythic III", "mythic"

    def create_layout(self):
        self.container = ttk.Frame(self.master, style="TFrame")
        self.container.grid(row=0, column=0, sticky="nsew")
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(1, weight=1)

    def create_input_frame(self):
        self.search_frame = ttk.Frame(self.container, style="TFrame")
        self.search_frame.grid(row=0, column=0, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=0)
        self.container.grid_columnconfigure(0, weight=0)

        self.hero_id_frame = ttk.Frame(self.search_frame, style="TFrame")
        self.hero_id_frame.grid(row=15, column=0, columnspan=4, sticky="nsew")

        self.init_duel_type_selection(self.search_frame)
        self.init_selection(
            self.search_frame,
            "Select Stat",
            self.stat_selections,
            1,
            self.get_stat_names(),
        )
        self.init_selection(
            self.search_frame,
            "Select Background",
            self.background_selections,
            2,
            self.get_background_names(),
        )
        self.init_buttons(self.search_frame)
        self.init_entry_fee_selection(self.search_frame)
        self.init_realm_selection(self.search_frame)
        self.init_duel_limit_entry(self.search_frame)
        self.create_gas_settings(self.search_frame)

    def create_output_frame(self):
        self.results_frame = ttk.Frame(self.container, style="TFrame")
        self.results_frame.grid(row=0, column=1, sticky="nsew", padx=10)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(1, weight=1)

        self.output_frame = ttk.Frame(self.results_frame, style="TFrame")
        self.output_frame.grid(row=0, column=0, sticky="nsew")
        self.results_frame.grid_rowconfigure(0, weight=1)
        self.results_frame.grid_columnconfigure(0, weight=1)

        self.log_output = tk.Text(self.output_frame, bg="black", fg="white")
        self.log_output.grid(row=0, column=0, sticky="nsew")
        self.output_frame.grid_rowconfigure(0, weight=1)
        self.output_frame.grid_columnconfigure(0, weight=1)

        # Add scrollbar to duel log output
        self.log_scrollbar = ttk.Scrollbar(
            self.output_frame, orient="vertical", command=self.log_output.yview
        )
        self.log_scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_output["yscrollcommand"] = self.log_scrollbar.set

        # Add queue display for heroes
        self.queue_display_frame = ttk.Frame(self.results_frame, style="TFrame")
        self.queue_display_frame.grid(row=1, column=0, sticky="nsew")
        self.queue_display_text = tk.Text(
            self.queue_display_frame, bg="black", fg="white", width=50
        )
        self.queue_display_text.grid(row=0, column=0, sticky="nsew")
        self.queue_display_frame.grid_rowconfigure(0, weight=1)
        self.queue_display_frame.grid_columnconfigure(0, weight=1)

        # Add scrollbar to queue display
        self.queue_scrollbar = ttk.Scrollbar(
            self.queue_display_frame,
            orient="vertical",
            command=self.queue_display_text.yview,
        )
        self.queue_scrollbar.grid(row=0, column=1, sticky="ns")
        self.queue_display_text["yscrollcommand"] = self.queue_scrollbar.set

    def init_selection(
        self, master, label_text, selection_set, offset, selection_names
    ):
        ttk.Label(master, text=label_text).grid(
            row=offset * 6, column=0, columnspan=4, sticky="nw"
        )
        buttons_frame = ttk.Frame(master)
        buttons_frame.grid(row=1 + offset * 6, column=0, columnspan=4, sticky="ew")

        class_buttons = {}
        for index, (number, name) in enumerate(selection_names.items()):
            btn = tk.Button(
                buttons_frame,
                text=name,
                bg="black",
                fg="white",
                highlightbackground="white",
                highlightcolor="white",
                highlightthickness=2,
                bd=5,
                command=lambda cn=number, s=selection_set: self.toggle_selection(
                    cn, s, class_buttons
                ),
            )
            btn.grid(
                row=(index // 4 + 1), column=index % 4, sticky="ew", padx=5, pady=2
            )
            class_buttons[number] = btn

        buttons_frame.grid_columnconfigure(tuple(range(4)), weight=1)

        if label_text == "Select Stat":
            self.stat_buttons = class_buttons
        elif label_text == "Select Background":
            self.background_buttons = class_buttons

    def toggle_selection(self, class_number, selection_set, class_buttons):
        for btn in class_buttons.values():
            btn.config(bg="black", fg="white")
        selection_set.clear()
        if class_number not in selection_set:
            selection_set.add(class_number)
            class_buttons[class_number].config(bg="green", fg="white")

    def init_duel_limit_entry(self, master):
        self.duel_limit_label = ttk.Label(master, text="Duel Limit:")
        self.duel_limit_label.grid(row=30, column=0, padx=0, pady=0, sticky="w")

        self.duel_limit_entry = ttk.Entry(master, width=10)
        self.duel_limit_entry.grid(row=30, column=1, padx=0, pady=5, sticky="w")

        self.password_label = ttk.Label(master, text="Password:")
        self.password_label.grid(row=30, column=2, padx=0, pady=0, sticky="w")

        self.password_entry = ttk.Entry(master, width=10, show="*")
        self.password_entry.grid(row=30, column=3, padx=0, pady=5, sticky="w")

    def init_duel_type_selection(self, master):
        ttk.Label(master, text="Select Duel Type").grid(
            row=13, column=0, columnspan=4, sticky="w"
        )
        duel_type_buttons_frame = ttk.Frame(master)
        duel_type_buttons_frame.grid(row=14, column=0, columnspan=4, sticky="ew")

        duel_type_buttons = {"solo": 1, "squad": 3, "pack": 5, "warr": 9}
        for index, (duel_type, num_fields) in enumerate(duel_type_buttons.items()):
            btn = tk.Radiobutton(
                duel_type_buttons_frame,
                text=duel_type,
                variable=self.duel_type_selection,
                value=num_fields,
                bg="black",
                fg="white",
                selectcolor="green",
                activebackground="black",
                activeforeground="white",
                command=self.handle_duel_type_selection,
            )
            btn.grid(row=0, column=index, sticky="ew", padx=5, pady=2)

        # Add arrow buttons for hero selection
        hero_selection_frame = ttk.Frame(master)
        hero_selection_frame.grid(row=15, column=0, columnspan=4, sticky="ew")

        self.prev_hero_btn = tk.Button(
            hero_selection_frame,
            text="<",
            command=self.load_previous_heroes,
            bg="black",
            fg="white",
        )
        self.prev_hero_btn.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.next_hero_btn = tk.Button(
            hero_selection_frame,
            text=">",
            command=self.load_next_heroes,
            bg="black",
            fg="white",
        )
        self.next_hero_btn.grid(row=0, column=1, padx=5, pady=5, sticky="e")

        # Add the delete button next to the selection arrows
        self.delete_team_btn = tk.Button(
            hero_selection_frame,
            text="Delete Team",
            bg="red",
            fg="white",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=self.delete_current_team,
        )
        self.delete_team_btn.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

        # Add a placeholder frame for the hero ID entries
        self.hero_id_placeholder_frame = ttk.Frame(master, style="TFrame")
        self.hero_id_placeholder_frame.grid(
            row=16, column=0, columnspan=4, sticky="nsew"
        )

    def init_entry_fee_selection(self, master):
        self.entry_fee_frame = ttk.Frame(master, style="TFrame")
        self.entry_fee_frame.grid(row=22, column=0, columnspan=4, sticky="nsew")
        self.entry_fee_label = ttk.Label(self.entry_fee_frame, text="Select entry fee")
        self.entry_fee_label.grid(row=0, column=0, columnspan=4, sticky="w")
        self.entry_fee_label.grid_remove()

        self.entry_fee_buttons = {}
        entry_fees = {
            "solo": [0.1, 0.5, 1],
            "squad": [0.2, 1, 2],
            "pack": [0.6, 3, 6],
            "warr": [2, 10, 20],
        }
        for duel_type, fees in entry_fees.items():
            button_frame = ttk.Frame(self.entry_fee_frame)
            button_frame.grid(row=1, column=0, columnspan=4, sticky="ew")
            self.entry_fee_buttons[duel_type] = []
            for fee in fees:
                btn = tk.Button(
                    button_frame,
                    text=str(fee),
                    bg="black",
                    fg="white",
                    highlightbackground="white",
                    highlightcolor="white",
                    highlightthickness=2,
                    bd=5,
                    command=lambda f=fee, dt=duel_type: self.handle_entry_fee_selection(
                        f, dt
                    ),
                )
                btn.pack(side="left", padx=5, pady=2, expand=True, fill="x")
                self.entry_fee_buttons[duel_type].append(btn)
            button_frame.grid_remove()

    def init_realm_selection(self, master):
        self.realm_buttons_frame = ttk.Frame(master)
        self.realm_buttons_frame.grid(row=23, column=0, columnspan=4, sticky="ew")

        realm_label = ttk.Label(self.realm_buttons_frame, text="Realm")
        realm_label.grid(row=0, column=0, sticky="w")

        self.realm_buttons = {}
        realms = {"CV": "Crystalvale", "SD": "Serendale"}
        for idx, (code, name) in enumerate(realms.items()):
            button = tk.Button(
                self.realm_buttons_frame,
                text=name,
                bg="black",
                fg="white",
                highlightbackground="white",
                highlightcolor="white",
                highlightthickness=2,
                bd=5,
                command=lambda realm=code: self.handle_realm_selection(realm),
            )
            button.grid(row=0, column=idx + 1, padx=5, pady=2, sticky="ew")
            self.realm_buttons[code] = button

    def handle_realm_selection(self, selected_realm):
        for button in self.realm_buttons.values():
            button.config(bg="black", fg="white")
        self.realm_buttons[selected_realm].config(bg="green", fg="white")
        self.current_realm = selected_realm

        # Update gas settings UI
        self.update_gas_settings_ui()

        if (
            self.current_realm and not self.duel_queue
        ):  # Prevent contract change if duels are ongoing
            if self.current_realm == "CV":
                duel_contract_address = CRYSTALVALE_CONTRACT_ADDRESS
                rpc_server = "https://subnets.avax.network/defi-kingdoms/dfk-chain/rpc"
            else:
                duel_contract_address = SERENDALE_CONTRACT_ADDRESS
                rpc_server = "https://klaytn.rpc.defikingdoms.com/"

            abi = load_abi("duel_abi.json", self.async_log_to_ui)
            if abi:
                self.duel_contract = DuelContract(
                    rpc_server, duel_contract_address, abi, self.async_log_to_ui
                )
                if self.duel_contract.contract:
                    self.update_class_bonuses()

    def update_gas_settings_ui(self):
        if self.current_realm:
            # Fetch current input values
            current_max_fee = self.max_fee_per_gas_entry.get()
            current_priority_fee = self.priority_fee_per_gas_entry.get()

            # Update the realm settings with current input values
            self.gas_settings[self.current_realm] = {
                "maxFeePerGas": current_max_fee,
                "maxPriorityFeePerGas": current_priority_fee,
            }

            # Update the UI entries with current values
            self.max_fee_per_gas_entry.set(current_max_fee)
            self.priority_fee_per_gas_entry.set(current_priority_fee)

    def handle_duel_type_selection(self):
        selected_duel_type = self.duel_type_selection.get()

        for label, entry in self.hero_id_fields:
            label.destroy()
            entry.destroy()
        self.hero_id_fields = []

        for i in range(selected_duel_type):
            label = ttk.Label(self.hero_id_placeholder_frame, text=f"Hero {i + 1} ID:")
            entry = ttk.Entry(self.hero_id_placeholder_frame)
            label.grid(row=i, column=0, sticky="w", padx=5, pady=5)
            entry.grid(row=i, column=1, sticky="ew", padx=5, pady=5)
            self.hero_id_fields.append((label, entry))

        for frame in self.entry_fee_buttons.values():
            for btn in frame:
                btn.master.grid_remove()
        duel_type_str = map_value("type", selected_duel_type, reverse=True)
        if duel_type_str in self.entry_fee_buttons:
            button_frame = self.entry_fee_buttons[duel_type_str][0].master
            button_frame.grid()
            self.entry_fee_label.grid()

        self.realm_buttons_frame.grid()

        if str(selected_duel_type) in self.duel_settings:
            settings = self.duel_settings[str(selected_duel_type)]
            stat = settings.get("stat")
            background = settings.get("background")
            realm = settings.get("realm")
            entry_fee = settings.get("entry_fee")
            hero_ids_list = settings.get("hero_ids_list", [])
            current_index = settings.get("current_hero_index", 0)

            if stat is not None:
                self.stat_selections.clear()
                self.stat_selections.add(stat)
                self.toggle_selection(stat, self.stat_selections, self.stat_buttons)
            if background is not None:
                self.background_selections.clear()
                self.background_selections.add(background)
                self.toggle_selection(
                    background, self.background_selections, self.background_buttons
                )

            if realm:
                self.handle_realm_selection(realm)

            if entry_fee:
                self.handle_entry_fee_selection(
                    entry_fee, map_value("type", selected_duel_type, reverse=True)
                )

            self.update_hero_id_fields(hero_ids_list, current_index)

    def pause_duel(self):
        self.pause_event.clear()
        self.async_log_to_ui("Paused")

    def resume_duel(self):
        self.pause_event.set()
        self.async_log_to_ui("Resumed")

    def toggle_pause_resume(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.async_log_to_ui("Paused")
            self.pause_resume_btn.config(text="Resume")
        else:
            self.pause_event.set()
            self.async_log_to_ui("Resumed")
            self.pause_resume_btn.config(text="Pause")

    def restart_duel(self):
        # Restart the entire application
        self.async_log_to_ui("Restarting application.")
        python = sys.executable
        os.execv(python, [python] + sys.argv)

    def undo_last_team(self):
        if self.duel_queue:
            self.duel_queue.pop()
            self.async_log_to_ui(f"Removed team from the queue")
            self.update_queue_display()
        else:
            self.async_log_to_ui("No teams to remove.")

    def reset_ui(self):
        self.clear_hero_id_fields()
        self.duel_type_selection.set(0)
        self.stat_selections.clear()
        self.background_selections.clear()

        for btn in self.stat_buttons.values():
            btn.config(bg="black", fg="white")

        for btn in self.background_buttons.values():
            btn.config(bg="black", fg="white")

        for fee_buttons in self.entry_fee_buttons.values():
            for btn in fee_buttons:
                btn.config(bg="black", fg="white")

        for btn in self.realm_buttons.values():
            btn.config(bg="black", fg="white")

        self.current_realm = None
        self.log_output.delete(1.0, tk.END)
        self.password_entry.delete(0, tk.END)

    def init_buttons(self, master):
        button_frame = ttk.Frame(master, style="TFrame")
        button_frame.grid(row=31, column=0, columnspan=4, sticky="ew")

        self.go_champion_btn = tk.Button(
            button_frame,
            text="Go For Champion",
            bg="gold",
            fg="black",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=lambda: self.process_duel("Champion"),
        )
        self.go_champion_btn.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.queue_set_number_btn = tk.Button(
            button_frame,
            text="Queue To Limit",
            bg="green",
            fg="white",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=lambda: self.process_duel("Queue"),
        )
        self.queue_set_number_btn.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.start_queue_btn = tk.Button(
            button_frame,
            text="Start Queue",
            bg="purple",
            fg="white",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=self.start_duel_queue,
        )
        self.start_queue_btn.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

        toggle_button_frame = ttk.Frame(master, style="TFrame")
        toggle_button_frame.grid(row=32, column=0, columnspan=4, sticky="ew")

        self.pause_resume_btn = tk.Button(
            toggle_button_frame,
            text="Pause",
            bg="blue",
            fg="white",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=self.toggle_pause_resume,
        )
        self.pause_resume_btn.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.restart_btn = tk.Button(
            toggle_button_frame,
            text="Restart",
            bg="red",
            fg="white",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=self.restart_duel,
        )
        self.restart_btn.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.undo_btn = tk.Button(
            toggle_button_frame,
            text="Undo",
            bg="orange",
            fg="white",
            highlightbackground="white",
            highlightcolor="white",
            highlightthickness=2,
            bd=5,
            command=self.undo_last_team,
        )
        self.undo_btn.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

    def get_selected_duel_type(self):
        return self.duel_type_selection.get()

    def get_selected_entry_fee(self):
        selected_duel_type = map_value(
            "type", self.get_selected_duel_type(), reverse=True
        )
        if selected_duel_type in self.entry_fee_buttons:
            selected_button = next(
                (
                    btn
                    for btn in self.entry_fee_buttons[selected_duel_type]
                    if btn.cget("bg") == "green"
                ),
                None,
            )
            if selected_button:
                return selected_button.cget("text")
        return ""

    def handle_entry_fee_selection(self, fee, duel_type):
        for btn in self.entry_fee_buttons[duel_type]:
            btn.config(bg="black", fg="white")
        clicked_button = next(
            (
                b
                for b in self.entry_fee_buttons[duel_type]
                if b.cget("text") == str(fee)
            ),
            None,
        )
        if clicked_button:
            clicked_button.config(bg="green", fg="white")

    def decrypt_key(self, key_file_path, password_provided):
        try:
            with open(key_file_path, "rb") as f:
                salt = f.read(16)
                encrypted_key = f.read()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_provided.encode()))
            fernet = Fernet(key)
            decrypted_key = fernet.decrypt(encrypted_key).decode()
            self.async_log_to_ui(f"Private key decrypted")
            return decrypted_key
        except Exception as e:
            self.async_log_to_ui(f"Error decrypting key: {e}")
            return None

    def validate_inputs(self):
        # Check if stat is selected
        if not self.stat_selections:
            messagebox.showerror("Input Error", "Please select a stat for each team.")
            return False

        # Check if background is selected
        if not self.background_selections:
            messagebox.showerror(
                "Input Error", "Please select a background for each team."
            )
            return False

        # Check if hero IDs are entered
        if not all(entry.get() for _, entry in self.hero_id_fields):
            messagebox.showerror("Input Error", "Please enter hero IDs for each team.")
            return False

        # Check if entry fee is selected
        if not self.get_selected_entry_fee():
            messagebox.showerror(
                "Input Error", "Please select an entry fee for each team."
            )
            return False

        # Check if realm is selected
        if not self.current_realm:
            messagebox.showerror("Input Error", "Please select a realm for each team.")
            return False

        # Check if duel limit is entered
        if not self.duel_limit_entry.get():
            messagebox.showerror(
                "Input Error", "Please enter a duel limit for each team."
            )
            return False

        return True

    def process_duel(self, button_type):
        if not self.validate_inputs():
            return

        selected_duel_type = self.get_selected_duel_type()
        selected_entry_fee = self.get_selected_entry_fee()
        selected_stat = next(iter(self.stat_selections), None)
        selected_background = next(iter(self.background_selections), None)
        hero_ids = [entry.get() for _, entry in self.hero_id_fields]
        duel_limit = int(self.duel_limit_entry.get())
        realm = self.current_realm
        # Add the settings to the queue
        team_settings = {
            "button_type": button_type,
            "duel_type": selected_duel_type,
            "entry_fee": selected_entry_fee,
            "stat": selected_stat,
            "background": selected_background,
            "hero_ids": hero_ids,
            "realm": realm,
            "duel_limit": duel_limit,
        }

        # Save the settings to the duel queue
        self.duel_queue.append(team_settings)

        # Save the configuration
        self.save_config()

        # Update the queue display in the UI
        self.update_queue_display()

    def update_queue_display(self):
        # Clear the current queue display
        self.queue_display_text.delete(1.0, tk.END)

        # Display each item in the queue
        for i, team in enumerate(self.duel_queue):
            team_info = (
                f"Team {i + 1}:\n"
                f"  Mode: {team['button_type']}\n"
                f"  Duel Limit: {team['duel_limit']}\n"
                f"  Realm: {team['realm']}\n"
                f"  Duel Type: {map_value('type', team['duel_type'], reverse=True)}\n"
                f"  Entry Fee: {team['entry_fee']}\n"
                f"  Stat: {map_value('stat', team['stat'], reverse=True)}\n"
                f"  Background: {map_value('background', team['background'], reverse=True)}\n"
                f"  Hero IDs: {', '.join(team['hero_ids'])}\n\n"
            )
            self.queue_display_text.insert(tk.END, team_info)

        self.queue_display_text.see(tk.END)

    def report_logs(
        self,
        button_type,
        duel_type,
        entry_fee,
        stat,
        background,
        hero_ids,
        duel_limit,
        realm,
    ):
        stat_name = (
            map_value("stat", stat, reverse=True) if stat is not None else "None"
        )
        background_name = (
            map_value("background", background, reverse=True)
            if background is not None
            else "None"
        )
        duel_type_name = (
            map_value("type", duel_type, reverse=True)
            if duel_type is not None
            else "None"
        )

        log_message = (
            f"\nCurrent Team:\n"
            f"Mode: {button_type}\n"
            f"Duel Limit: {duel_limit}\n"
            f"Realm: {realm}\n"
            f"Duel Type: {duel_type_name}\n"
            f"Entry Fee: {entry_fee}\n"
            f"Stat: {stat_name}\n"
            f"Background: {background_name}\n"
            f"Hero IDs: {', '.join(hero_ids)}\n\n"
        )
        self.async_log_to_ui(log_message)

    def start_duel_queue(self):
        self.async_log_to_ui("Attempting to start dueling queue.")
        time.sleep(0.5)
        if not self.duel_task:
            self.duel_task = threading.Thread(target=self.duel_loop)
            self.duel_task.start()
            self.async_log_to_ui("Dueling queue started.")
        else:
            self.async_log_to_ui("Dueling queue is already running.")

    def duel_loop(self):
        try:
            password = self.password_entry.get()
            script_dir = os.getcwd()  # Use current working directory
            key_file_name = [f for f in os.listdir(script_dir) if f.endswith(".key")]
            if key_file_name:
                key_file_name = key_file_name[0]
                self.private_key = self.decrypt_key(
                    os.path.join(script_dir, key_file_name), password
                )
                if not self.private_key:
                    self.async_log_to_ui(
                        "Failed to decrypt the private key. Exiting duel loop."
                    )
                    return
            else:
                self.async_log_to_ui(
                    "No .key file found in the script directory. Exiting duel loop."
                )
                return

            while self.duel_queue:
                current_team = self.duel_queue[
                    0
                ]  # Get the first team in the queue without removing it

                button_type = current_team["button_type"]
                selected_duel_type = current_team["duel_type"]
                selected_entry_fee = current_team["entry_fee"]
                selected_stat = current_team["stat"]
                selected_background = current_team["background"]
                hero_ids = current_team["hero_ids"]
                realm = current_team["realm"]
                duel_limit = current_team["duel_limit"]

                # Ensure the contract and realm are properly set
                self.handle_realm_selection(realm)

                # Log the current team's dueling session
                self.report_logs(
                    button_type,
                    selected_duel_type,
                    selected_entry_fee,
                    selected_stat,
                    selected_background,
                    hero_ids,
                    duel_limit,
                    realm,
                )

                # Run the dueling process
                self.run_dueling_process(
                    button_type,
                    selected_duel_type,
                    selected_entry_fee,
                    selected_stat,
                    selected_background,
                    hero_ids,
                    duel_limit,
                    realm,
                )
                # If the dueling process completes successfully, remove the team from the queue
                self.duel_queue.pop(0)
                # Update the queue display
                self.update_queue_display()

            self.duel_task = None
            self.async_log_to_ui("All duels completed.\n")

        except Exception as e:
            self.async_log_to_ui(f"Error processing team: {e}")

    def run_dueling_process(
        self,
        button_type,
        selected_duel_type,
        selected_entry_fee,
        selected_stat,
        selected_background,
        hero_ids,
        duel_limit,
        realm,
    ):
        try:
            max_fee_per_gas = int(self.max_fee_per_gas_entry.get())
            priority_fee_per_gas = int(self.priority_fee_per_gas_entry.get())

            gas_price = {
                "maxFeePerGas": max_fee_per_gas,
                "maxPriorityFeePerGas": priority_fee_per_gas,
            }

            w3 = self.duel_contract.w3
            account_address = w3.eth.account.from_key(self.private_key).address
            nonce = w3.eth.get_transaction_count(account_address)
            duel_type_number = selected_duel_type
            hero_id_int = [int(id_str) for id_str in hero_ids if id_str.isdigit()]

            duel_count_start = self.duel_contract.get_hero_duel_count_for_day(
                hero_id_int, duel_type_number
            )
            self.async_log_to_ui(f"Hero(es) Duel Count: {duel_count_start}")
            time.sleep(0.3)

            # Get initial win streak
            initial_win_streak = self.duel_contract.get_win_streak(
                account_address, duel_type_number
            )
            win_streak = initial_win_streak
            self.async_log_to_ui(f"Initial win streak: {win_streak}")

            # Determine the daily duel limit for the selected duel type
            daily_duel_limits = {1: 10, 3: 30, 5: 50, 9: 90}
            max_daily_duels = daily_duel_limits.get(duel_type_number, 10)

            total_duels_completed = 0
            reached_duel_limit = False
            reached_daily_limit = False

            while not reached_duel_limit and not reached_daily_limit:
                self.pause_event.wait()

                # Matchmaking for pending duels
                pending_duels = self.duel_contract.get_player_duel_entries(
                    account_address
                )
                time.sleep(0.3)
                if pending_duels:
                    self.async_log_to_ui("\nMatchmaking")
                    try:
                        self.duel_contract.matchmake(
                            self.private_key, nonce, gas_price, 60
                        )
                        nonce = w3.eth.get_transaction_count(account_address)
                    except Exception as e:
                        if "nonce too low" in str(e):
                            self.async_log_to_ui("Nonce too low, incrementing nonce.")
                            nonce += 1
                        else:
                            self.async_log_to_ui(f"Matchmaking error: {str(e)}")

                time.sleep(5)

                # Completing active duels
                active_duels = self.duel_contract.get_active_duels(account_address)
                initial_active_duels_count = len(active_duels)
                self.async_log_to_ui(f"\n{initial_active_duels_count} active duels")
                time.sleep(0.3)

                while active_duels:
                    nonce = w3.eth.get_transaction_count(account_address)
                    self.pause_event.wait()
                    try:
                        max_duels_per_tx = calculate_max_duels_per_tx(
                            self.duel_contract.contract, active_duels[0]["id"], realm
                        )
                        num_to_complete = min(max_duels_per_tx, len(active_duels))
                        self.async_log_to_ui(f"\nCompleting {num_to_complete} duels")
                        receipt = self.duel_contract.complete_multiple_duels(
                            num_to_complete, self.private_key, nonce, gas_price, 60
                        )
                        if receipt:
                            nonce = w3.eth.get_transaction_count(account_address)
                        time.sleep(2)

                        # Update win streak
                        new_win_streak = self.duel_contract.get_win_streak(
                            account_address, duel_type_number
                        )
                        if new_win_streak != win_streak:
                            win_streak = new_win_streak

                    except Exception as e:
                        if "nonce too low" in str(e) or "already known" in str(e):
                            self.async_log_to_ui("Nonce too low, incrementing nonce.")
                            nonce += 1
                        else:
                            self.async_log_to_ui(f"Transaction error: {str(e)}")
                            break
                    time.sleep(0.3)
                    new_active_duels = self.duel_contract.get_active_duels(
                        account_address
                    )
                    if new_active_duels != active_duels:
                        self.async_log_to_ui(f"\nCurrent win streak: {win_streak}")
                        total_duels_completed += num_to_complete
                        active_duels = new_active_duels

                    time.sleep(0.3)
                    # Fetch and display player score
                    player_score = self.duel_contract.get_player_score(
                        account_address, duel_type_number
                    )
                    rank_name, rank_tag = self.get_rank_and_tag(player_score)
                    self.log_to_ui(f"Current Rank: {player_score} ", None)
                    self.log_to_ui(f"{rank_name}", rank_tag)

                # After completing all active duels, check for pending duels and perform matchmaking
                pending_duels = self.duel_contract.get_player_duel_entries(
                    account_address
                )
                if pending_duels:
                    self.pause_event.wait()

                    self.async_log_to_ui("\nMatchmaking")
                    try:
                        self.duel_contract.matchmake(
                            self.private_key, nonce, gas_price, 60
                        )
                        nonce = w3.eth.get_transaction_count(account_address)
                    except Exception as e:
                        if "nonce too low" in str(e):
                            self.async_log_to_ui("Nonce too low, incrementing nonce.")
                            nonce += 1
                        else:
                            self.async_log_to_ui(f"Matchmaking error: {str(e)}")
                    time.sleep(5)
                    continue

                # Check duel limits after completing all active duels
                duel_count_current = self.duel_contract.get_hero_duel_count_for_day(
                    hero_id_int, duel_type_number
                )
                daily_duels_remaining = max_daily_duels - duel_count_current[0]

                duels_remaining = duel_limit - total_duels_completed
                self.async_log_to_ui(
                    f"\nTotal duels completed: {total_duels_completed}"
                )
                self.async_log_to_ui(
                    f"Duels remaining in duel limit: {duels_remaining}"
                )
                self.async_log_to_ui(
                    f"Duels remaining in daily limit: {daily_duels_remaining}"
                )
                time.sleep(0.3)
                active_duels = self.duel_contract.get_active_duels(account_address)
                if not active_duels:
                    if total_duels_completed >= duel_limit:
                        reached_duel_limit = True
                        self.async_log_to_ui("Reached duel limit")
                        break

                    if daily_duels_remaining <= 0:
                        reached_daily_limit = True
                        self.async_log_to_ui("Reached daily limit for hero(es)")
                        break

                    queue_number = min(daily_duels_remaining, duels_remaining)

                    if button_type == "Champion":
                        queue_number = min(queue_number, 5 - win_streak)
                        player_score = self.duel_contract.get_player_score(
                            account_address, duel_type_number
                        )
                        if win_streak >= 5 and player_score >= 500:
                            if queue_number <= 0:
                                self.async_log_to_ui("Ready to challenge champion")
                                break
                        elif player_score < 500:
                            queue_number = min(daily_duels_remaining, duels_remaining)

                    if queue_number <= 0:
                        break
                    self.pause_event.wait()

                    self.async_log_to_ui(f"\nEntering {queue_number} duels in lobby")
                    try:
                        self.duel_contract.enter_duel_lobby(
                            selected_duel_type,
                            hero_id_int,
                            selected_entry_fee,
                            selected_background,
                            selected_stat,
                            queue_number,
                            self.private_key,
                            nonce,
                            gas_price,
                            60,
                        )
                        nonce = w3.eth.get_transaction_count(account_address)
                    except Exception as e:
                        if "already entered this lobby" in str(
                            e
                        ) or "pending open duel" in str(e):
                            self.async_log_to_ui(
                                "Already entered this lobby or pending open duel. Continuing."
                            )
                            continue
                        elif "nonce too low" in str(e):
                            self.async_log_to_ui("Nonce too low, incrementing nonce.")
                            nonce += 1
                        else:
                            self.async_log_to_ui(f"Error entering duel lobby: {str(e)}")
                            break
                    time.sleep(5)

        except Exception as e:
            self.async_log_to_ui(f"An error occurred: {str(e)}")

    @staticmethod
    def get_stat_names():
        return {v: k for k, v in STAT_MAPPING.items()}

    @staticmethod
    def get_background_names():
        return {v: k for k, v in BACKGROUND_MAPPING.items()}

    def save_config(self):
        selected_duel_type = self.get_selected_duel_type()
        duel_type_str = map_value("type", selected_duel_type, reverse=True)

        new_hero_ids = [entry.get() for _, entry in self.hero_id_fields]
        new_hero_entry = {
            "hero_ids": new_hero_ids,
            "stat": next(iter(self.stat_selections), None),
            "background": next(iter(self.background_selections), None),
            "entry_fee": self.get_selected_entry_fee(),
            "realm": self.current_realm,
        }

        if duel_type_str in self.duel_settings:
            existing_settings = self.duel_settings[duel_type_str]
            existing_hero_ids_list = existing_settings.get("hero_ids_list", [])
            if new_hero_entry not in existing_hero_ids_list:
                existing_hero_ids_list.append(new_hero_entry)
            existing_settings["hero_ids_list"] = existing_hero_ids_list
            existing_settings["current_hero_index"] = existing_hero_ids_list.index(
                new_hero_entry
            )
        else:
            duel_type_settings = {
                "hero_ids_list": [new_hero_entry],
                "current_hero_index": 0,
            }
            self.duel_settings[duel_type_str] = duel_type_settings

        config = {"duel_settings": self.duel_settings}

        try:
            script_dir = os.getcwd()  # Use current working directory
            config_file_path = os.path.join(script_dir, self.CONFIG_FILE)
            with open(config_file_path, "w") as config_file:
                json.dump(config, config_file)
        except Exception as e:
            self.async_log_to_ui(f"Error saving configuration: {e}")

    def delete_current_team(self):
        selected_duel_type = self.get_selected_duel_type()
        duel_type_str = map_value("type", selected_duel_type, reverse=True)
        if duel_type_str in self.duel_settings:
            current_index = self.duel_settings[duel_type_str].get(
                "current_hero_index", 0
            )
            hero_ids_list = self.duel_settings[duel_type_str].get("hero_ids_list", [])
            if hero_ids_list:
                hero_ids_list.pop(current_index)
                if not hero_ids_list:
                    del self.duel_settings[duel_type_str]
                    self.clear_hero_id_fields()
                    self.reset_ui()  # Reset UI when no teams are left
                else:
                    self.duel_settings[duel_type_str]["hero_ids_list"] = hero_ids_list
                    new_index = min(current_index, len(hero_ids_list) - 1)
                    self.duel_settings[duel_type_str]["current_hero_index"] = new_index
                    self.update_hero_id_fields(hero_ids_list, new_index)

                self.save_config()
                self.update_queue_display()
                self.async_log_to_ui("Team deleted.")
            else:
                self.async_log_to_ui("No teams to delete.")
        else:
            self.async_log_to_ui("No teams to delete.")

    def load_previous_heroes(self):
        selected_duel_type = self.get_selected_duel_type()
        duel_type_str = map_value("type", selected_duel_type, reverse=True)
        if duel_type_str in self.duel_settings:
            hero_ids_list = self.duel_settings[duel_type_str].get("hero_ids_list", [])
            if hero_ids_list:
                current_index = self.duel_settings[duel_type_str].get(
                    "current_hero_index", 0
                )
                if all(not entry.get() for _, entry in self.hero_id_fields):
                    current_index = 0
                else:
                    current_index = (current_index - 1) % len(hero_ids_list)
                self.duel_settings[duel_type_str]["current_hero_index"] = current_index
                self.update_hero_id_fields(hero_ids_list, current_index)

    def load_next_heroes(self):
        selected_duel_type = self.get_selected_duel_type()
        duel_type_str = map_value("type", selected_duel_type, reverse=True)
        if duel_type_str in self.duel_settings:
            hero_ids_list = self.duel_settings[duel_type_str].get("hero_ids_list", [])
            if hero_ids_list:
                current_index = self.duel_settings[duel_type_str].get(
                    "current_hero_index", -1
                )
                if all(not entry.get() for _, entry in self.hero_id_fields):
                    current_index = 0
                else:
                    current_index = (current_index + 1) % len(hero_ids_list)
                self.duel_settings[duel_type_str]["current_hero_index"] = current_index
                self.update_hero_id_fields(hero_ids_list, current_index)

    def update_hero_id_fields(self, hero_ids_list, current_index):
        self.clear_hero_id_fields()
        if not hero_ids_list or current_index >= len(hero_ids_list):
            return

        current_settings = hero_ids_list[current_index]
        hero_ids = current_settings.get("hero_ids", [])
        for i, hero_id in enumerate(hero_ids):
            label = ttk.Label(self.hero_id_placeholder_frame, text=f"Hero {i + 1} ID:")
            entry = ttk.Entry(self.hero_id_placeholder_frame)
            label.grid(row=i, column=0, sticky="w", padx=5, pady=5)
            entry.grid(row=i, column=1, sticky="ew", padx=5, pady=5)
            entry.insert(0, hero_id)
            self.hero_id_fields.append((label, entry))

        # Update the settings for stat, background, fee, and realm
        stat = current_settings.get("stat")
        background = current_settings.get("background")
        entry_fee = current_settings.get("entry_fee")
        realm = current_settings.get("realm")
        if stat is not None:
            self.stat_selections.clear()
            self.stat_selections.add(stat)
            self.toggle_selection(stat, self.stat_selections, self.stat_buttons)
        if background is not None:
            self.background_selections.clear()
            self.background_selections.add(background)
            self.toggle_selection(
                background, self.background_selections, self.background_buttons
            )
        if entry_fee:
            self.handle_entry_fee_selection(
                entry_fee,
                map_value("type", self.get_selected_duel_type(), reverse=True),
            )
        if realm:
            self.handle_realm_selection(realm)

    def clear_hero_id_fields(self):
        for label, entry in self.hero_id_fields:
            label.destroy()
            entry.destroy()
        self.hero_id_fields = []

    @staticmethod
    def load_config(file_name):
        try:
            script_dir = os.getcwd()  # Use current working directory
            config_file_path = os.path.join(script_dir, file_name)
            if (
                not os.path.exists(config_file_path)
                or os.path.getsize(config_file_path) == 0
            ):
                return {}

            with open(config_file_path, "r") as config_file:
                return json.load(config_file)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading configuration: {e}")
            return {}

    def apply_config(self):
        config = self.load_config(self.CONFIG_FILE)
        self.duel_settings = config.get("duel_settings", {})

        selected_duel_type = self.get_selected_duel_type()
        duel_type_str = map_value("type", selected_duel_type, reverse=True)
        if duel_type_str in self.duel_settings:
            settings = self.duel_settings[duel_type_str]
            hero_ids_list = settings.get("hero_ids_list", [])
            current_index = settings.get("current_hero_index", 0)
            self.update_hero_id_fields(hero_ids_list, current_index)

    def update_class_bonuses(self):
        try:
            if not self.duel_contract or not self.duel_contract.contract:
                self.async_log_to_ui("Duel contract is not initialized.")
                return

            class_bonuses = self.duel_contract.get_current_class_bonuses()
            if class_bonuses and len(class_bonuses) >= 2:
                bonus1 = [
                    self.class_names.get(num, None)
                    for num in class_bonuses[0]
                    if num in self.class_names
                ]
                bonus2 = [
                    self.class_names.get(num, None)
                    for num in class_bonuses[1]
                    if num in self.class_names
                ]

                bonuses_text1 = "Class Bonus 1: " + ", ".join(bonus1)
                bonuses_text2 = "Class Bonus 2: " + ", ".join(bonus2)

                if hasattr(self, "class_bonuses_label1"):
                    self.class_bonuses_label1.config(text=bonuses_text1)
                else:
                    self.class_bonuses_label1 = ttk.Label(
                        self.search_frame, text=bonuses_text1, style="TLabel"
                    )
                    self.class_bonuses_label1.grid(
                        row=0, column=0, columnspan=4, sticky="w", pady=5
                    )

                if hasattr(self, "class_bonuses_label2"):
                    self.class_bonuses_label2.config(text=bonuses_text2)
                else:
                    self.class_bonuses_label2 = ttk.Label(
                        self.search_frame, text=bonuses_text2, style="TLabel"
                    )
                    self.class_bonuses_label2.grid(
                        row=1, column=0, columnspan=4, sticky="w", pady=5
                    )
            else:
                self.async_log_to_ui("Failed to get both class bonuses.")

        except Exception as e:
            self.async_log_to_ui(f"Failed to get class bonuses: {str(e)}")


def main():
    root = tk.Tk()
    app = DuelApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
