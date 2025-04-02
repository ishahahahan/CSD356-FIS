import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import base64
import os

from src.encryption import EncryptionManager
from src.password_generator import PasswordGenerator
from src.password_checker import PasswordChecker
from src.vault import PasswordVault

class PasswordManagerApp:
    def __init__(self):
        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("Secure Password Manager")
        self.root.geometry("500x600")
        
        # Initialize password vault
        self.password_vault = None
        
        # Track encryption key
        self.encryption_key = None
        
        # Create vault selection frame
        self.create_vault_selection_frame()
        
    def create_password_entry_with_toggle(self, parent, placeholder_text="Enter Password", show_strength=True):
        """
        Create a password entry field with toggle visibility button and strength meter
        
        Args:
            parent: Parent widget
            placeholder_text: Placeholder text for entry
            show_strength: Whether to show the password strength meter
            
        Returns:
            tuple: (frame, entry_widget, strength_frame)
        """
        # Create a frame to hold the entry and toggle button
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        
        # Create the password entry
        entry = ctk.CTkEntry(frame, show="*", placeholder_text=placeholder_text, width=220)
        entry.pack(side=tk.LEFT, padx=(0, 5))
        
        # Password visibility state
        password_visible = False
        
        # Toggle button
        def toggle_password_visibility():
            nonlocal password_visible
            password_visible = not password_visible
            entry.configure(show="" if password_visible else "*")
            toggle_button.configure(text="Hide" if password_visible else "Show")
            
        toggle_button = ctk.CTkButton(frame, text="Show", width=60, 
                                     command=toggle_password_visibility)
        toggle_button.pack(side=tk.RIGHT)
        
        # Strength meter frame (outside the password frame)
        strength_frame = None
        if show_strength:
            strength_frame = ctk.CTkFrame(parent, fg_color="transparent", height=50)
            strength_indicator = ctk.CTkProgressBar(strength_frame, width=280)
            strength_indicator.pack(pady=(0, 5))
            strength_indicator.set(0)  # Initial value
            
            strength_label = ctk.CTkLabel(strength_frame, text="Password Strength: Enter a password")
            strength_label.pack()
            
            # Update strength in real-time
            def update_strength_meter(event=None):
                password = entry.get()
                if not password:
                    strength_indicator.set(0)
                    strength_label.configure(text="Password Strength: Enter a password")
                    return
                
                # Get password strength details
                strength_result = PasswordChecker.check_password_strength(password)
                score = strength_result['score']
                
                # Update progress bar color and value
                strength_value = (score + 1) / 5  # Convert to 0-1 scale
                strength_indicator.set(strength_value)
                
                # Determine color and text based on score
                if score <= 1:
                    strength_indicator.configure(progress_color="red")
                    status = "Very Weak"
                elif score == 2:
                    strength_indicator.configure(progress_color="orange")
                    status = "Weak"
                elif score == 3:
                    strength_indicator.configure(progress_color="#93c47d")  # Light green
                    status = "Good"
                else:
                    strength_indicator.configure(progress_color="green")
                    status = "Strong"
                
                # If available, show feedback
                feedback = ""
                if 'feedback' in strength_result and 'warning' in strength_result['feedback']:
                    warning = strength_result['feedback']['warning']
                    if warning:
                        feedback = f" - {warning}"
                
                strength_label.configure(text=f"Password Strength: {status}{feedback}")
            
            # Bind event to update on key press
            entry.bind("<KeyRelease>", update_strength_meter)
        
        return frame, entry, strength_frame
    
    def create_vault_selection_frame(self):
        """Create the initial vault selection screen"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(main_frame, text="Password Manager", font=("Roboto", 24))
        title_label.pack(pady=(20, 30))
        
        # Get available vaults
        vaults = PasswordVault.list_vaults()
        
        if vaults:
            # Vault selection section
            selection_label = ctk.CTkLabel(main_frame, text="Select a Vault", font=("Roboto", 18))
            selection_label.pack(pady=(0, 10))
            
            # Frame for vault buttons
            vaults_frame = ctk.CTkScrollableFrame(main_frame, width=300, height=200)
            vaults_frame.pack(pady=10, fill='both', expand=True)
            
            # Add a button for each vault
            for vault_id, vault_name in vaults:
                def open_login(vid=vault_id):
                    self.password_vault = PasswordVault(vault_id=vid)
                    self.create_login_frame()
                
                vault_button = ctk.CTkButton(
                    vaults_frame, 
                    text=vault_name,
                    command=open_login,
                    height=40,
                    width=260
                )
                vault_button.pack(pady=5, padx=10)
        else:
            # No vaults message
            no_vaults_label = ctk.CTkLabel(
                main_frame, 
                text="No vaults found. Create a new vault to get started.",
                font=("Roboto", 14)
            )
            no_vaults_label.pack(pady=20)
        
        # Create New Vault Button
        create_vault_button = ctk.CTkButton(
            main_frame, 
            text="Create New Vault", 
            command=self.create_new_vault,
            height=50,
            width=200
        )
        create_vault_button.pack(pady=20)
        
    def create_login_frame(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Login Frame
        login_frame = ctk.CTkFrame(self.root)
        login_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(login_frame, text="Password Manager", font=("Roboto", 24))
        title_label.pack(pady=(20, 10))
        
        # Create password entry with toggle
        password_frame, self.master_password_entry, strength_frame = self.create_password_entry_with_toggle(
            login_frame, "Enter Master Password")
        password_frame.pack(pady=10, padx=20)
        if strength_frame:
            strength_frame.pack(pady=(0, 10))
        
        # Login Button
        login_button = ctk.CTkButton(login_frame, text="Login", command=self.login)
        login_button.pack(pady=10)
        
        # Back Button
        back_button = ctk.CTkButton(login_frame, text="Back to Vault Selection", 
                                   command=self.create_vault_selection_frame)
        back_button.pack(pady=10)
        
    def login(self):
        master_password = self.master_password_entry.get()
        
        if self.password_vault.verify_master_password(master_password):
            # Generate encryption key
            with open(self.password_vault.master_key_file, 'rb') as f:
                stored_data = f.read()
                salt = stored_data[:16]
                self.encryption_key, _ = EncryptionManager.generate_key(master_password, salt)
            
            # Open main vault interface
            self.create_vault_interface()
        else:
            messagebox.showerror("Login Failed", "Incorrect Master Password")
    
    def create_new_vault(self):
        # New Vault Creation Window
        new_vault_window = ctk.CTkToplevel(self.root)
        new_vault_window.title("Create New Vault")
        new_vault_window.geometry("400x380")  # Increased height for vault name
        new_vault_window.grab_set()  # Make window modal
        
        # Create a new vault instance
        self.password_vault = PasswordVault()
        
        # Vault Name
        name_label = ctk.CTkLabel(new_vault_window, text="Vault Name (Optional)")
        name_label.pack(pady=(20, 5))
        
        name_entry = ctk.CTkEntry(new_vault_window, placeholder_text=f"Vault {self.password_vault.vault_id[:8]}")
        name_entry.pack(pady=(0, 15))
        
        # Master Password Creation
        title_label = ctk.CTkLabel(new_vault_window, text="Create Master Password", font=("Roboto", 20))
        title_label.pack(pady=(0, 10))
        
        # Create password entry with toggle for new password
        password_frame, password_entry, strength_frame = self.create_password_entry_with_toggle(
            new_vault_window, "Enter Master Password")
        password_frame.pack(pady=10, padx=20)
        if strength_frame:
            strength_frame.pack(pady=(0, 10))
        
        # Create password entry with toggle for confirmation
        confirm_frame, confirm_entry, _ = self.create_password_entry_with_toggle(
            new_vault_window, "Confirm Master Password", show_strength=False)
        confirm_frame.pack(pady=10, padx=20)
        
        def create_vault():
            master_password = password_entry.get()
            confirm_password = confirm_entry.get()
            
            if master_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            try:
                self.encryption_key = self.password_vault.create_master_password(master_password)
                
                # Update vault name if provided
                vault_name = name_entry.get().strip()
                if vault_name:
                    print(vault_name)
                    # Update info file with custom name
                    info_file = os.path.join(self.password_vault.vault_dir, 
                                            f'{self.password_vault.vault_id}_info.json')
                    import json
                    # Read existing info first
                    with open(info_file, 'r') as f:
                        info = json.load(f)
                    # Update only the name
                    info['name'] = vault_name
                    # Write back
                    with open(info_file, 'w') as f:
                        json.dump(info, f)
                
                # Create master password and key
                messagebox.showinfo("Success", "Vault Created Successfully")
                new_vault_window.destroy()
                
                # Open the vault interface
                self.create_vault_interface()
                
            except ValueError as e:
                messagebox.showerror("Password Too Weak", str(e))
        
        create_button = ctk.CTkButton(new_vault_window, text="Create Vault", command=create_vault)
        create_button.pack(pady=10)
    
    def create_vault_interface(self):
        # Clear previous frame
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main Vault Frame
        vault_frame = ctk.CTkFrame(self.root)
        vault_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Vault Title
        title_label = ctk.CTkLabel(vault_frame, text="Password Vault", font=("Roboto", 24))
        title_label.pack(pady=(20, 10))
        
        # Service Entry
        service_label = ctk.CTkLabel(vault_frame, text="Service/Website")
        service_label.pack()
        service_entry = ctk.CTkEntry(vault_frame, placeholder_text="e.g., Google, Facebook")
        service_entry.pack(pady=5)
        
        # Username Entry
        username_label = ctk.CTkLabel(vault_frame, text="Username")
        username_label.pack()
        username_entry = ctk.CTkEntry(vault_frame)
        username_entry.pack(pady=5)
        
        # Password Entry with toggle and strength meter
        password_label = ctk.CTkLabel(vault_frame, text="Password")
        password_label.pack()
        password_frame, password_entry, strength_frame = self.create_password_entry_with_toggle(
            vault_frame, "Enter Password")
        password_frame.pack(pady=5)
        if strength_frame:
            strength_frame.pack(pady=(0, 10))
        
        # Generate Password Button
        def generate_password():
            generated_password = PasswordGenerator.generate_strong_password()
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generated_password)
            # Manually trigger the strength update
            password_entry.event_generate("<KeyRelease>")
        
        generate_button = ctk.CTkButton(vault_frame, text="Generate Strong Password", command=generate_password)
        generate_button.pack(pady=10)
        
        # Save Password Button
        def save_password():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            
            if not service or not username or not password:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            try:
                self.password_vault.add_password(service, username, password, self.encryption_key)
                messagebox.showinfo("Success", "Password saved successfully")
                
                # Clear entries
                service_entry.delete(0, tk.END)
                username_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                # Reset strength meter
                password_entry.event_generate("<KeyRelease>")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        save_button = ctk.CTkButton(vault_frame, text="Save Password", command=save_password)
        save_button.pack(pady=10)
        
        # Retrieve Password Section
        retrieve_label = ctk.CTkLabel(vault_frame, text="Retrieve Password", font=("Roboto", 18))
        retrieve_label.pack(pady=(20, 5))
        
        retrieve_service_entry = ctk.CTkEntry(vault_frame, placeholder_text="Enter Service")
        retrieve_service_entry.pack(pady=5)
        
        def retrieve_password():
            service = retrieve_service_entry.get()
            if not service:
                messagebox.showerror("Error", "Please enter a service")
                return
            
            username, password = self.password_vault.get_password(service, self.encryption_key)
            
            if username and password:
                messagebox.showinfo("Retrieved Password", f"Username: {username}\nPassword: {password}")
            else:
                messagebox.showerror("Error", "No password found for this service")
        
        retrieve_button = ctk.CTkButton(vault_frame, text="Retrieve Password", command=retrieve_password)
        retrieve_button.pack(pady=10)
        
        # Logout Button
        logout_button = ctk.CTkButton(vault_frame, text="Logout", 
                                     command=self.create_vault_selection_frame)
        logout_button.pack(pady=20)
    
    def run(self):
        self.root.mainloop()

def main():
    app = PasswordManagerApp()
    app.run()

if __name__ == "__main__":
    main()