import discord
from discord.ext import commands
from discord import app_commands
import subprocess
import os
import shutil
import zipfile
import aiohttp
import asyncio
import psutil
import platform
import requests
from datetime import datetime
from typing import Optional
import json
import sys

# ======================== CONFIGURATION ========================
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
JSONBIN_API_KEY = os.getenv('JSONBIN_API_KEY')  # Get from jsonbin.io
JSONBIN_BIN_ID = os.getenv('JSONBIN_BIN_ID')

# ======================== JSONBIN STORAGE ========================
class JSONBinStorage:
    def __init__(self, api_key, bin_id):
        self.api_key = api_key
        self.bin_id = bin_id
        self.base_url = f"https://api.jsonbin.io/v3/b/{bin_id}"
        self.headers = {
            "X-Master-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def get_users(self):
        """Fetch user data from JSONBin"""
        try:
            response = requests.get(f"{self.base_url}/latest", headers=self.headers)
            if response.status_code == 200:
                return response.json().get('record', {})
            return {}
        except Exception as e:
            print(f"Error fetching users: {e}")
            return {}
    
    def save_users(self, users_data):
        """Save user data to JSONBin"""
        try:
            response = requests.put(self.base_url, json=users_data, headers=self.headers)
            return response.status_code == 200
        except Exception as e:
            print(f"Error saving users: {e}")
            return False

# ======================== RBAC SYSTEM ========================
class RBACSystem:
    ROLES = ['admin', 'user', 'readonly']
    
    def __init__(self, storage):
        self.storage = storage
        self.users = self.storage.get_users()
        
        # Initialize with empty structure if needed
        if not self.users:
            self.users = {'admins': [], 'users': [], 'readonly': []}
            self.storage.save_users(self.users)
    
    def add_user(self, user_id: int, role: str):
        """Add user with specific role"""
        user_id = str(user_id)
        role = role.lower()
        
        if role not in self.ROLES:
            return False
        
        # Remove from other roles
        for r in self.ROLES:
            key = f"{r}s"
            if user_id in self.users.get(key, []):
                self.users[key].remove(user_id)
        
        # Add to new role
        key = f"{role}s"
        if key not in self.users:
            self.users[key] = []
        
        if user_id not in self.users[key]:
            self.users[key].append(user_id)
            self.storage.save_users(self.users)
        
        return True
    
    def remove_user(self, user_id: int):
        """Remove user from all roles"""
        user_id = str(user_id)
        removed = False
        
        for role in self.ROLES:
            key = f"{role}s"
            if user_id in self.users.get(key, []):
                self.users[key].remove(user_id)
                removed = True
        
        if removed:
            self.storage.save_users(self.users)
        
        return removed
    
    def get_role(self, user_id: int):
        """Get user's role"""
        user_id = str(user_id)
        
        for role in self.ROLES:
            key = f"{role}s"
            if user_id in self.users.get(key, []):
                return role
        
        return None
    
    def has_permission(self, user_id: int, required_role: str):
        """Check if user has required permission level"""
        role = self.get_role(user_id)
        
        if role is None:
            return False
        
        role_hierarchy = {'admin': 3, 'user': 2, 'readonly': 1}
        
        return role_hierarchy.get(role, 0) >= role_hierarchy.get(required_role, 0)
    
    def list_users(self):
        """List all users by role"""
        return self.users

# ======================== BOT SETUP ========================
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='/', intents=intents)
storage = JSONBinStorage(JSONBIN_API_KEY, JSONBIN_BIN_ID)
rbac = RBACSystem(storage)

# ======================== LOGGING UTILITY ========================
def log_command(user, command, status="SUCCESS"):
    """Log command execution to terminal"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] USER: {user} | CMD: {command} | STATUS: {status}")

async def send_error(ctx, error_msg):
    """Send error to both Discord and terminal"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] ERROR: {error_msg}")
    await ctx.response.send_message(f"❌ **Error:**\n```\n{error_msg}\n```", ephemeral=True)

# ======================== PERMISSION DECORATOR ========================
def requires_permission(role='readonly'):
    def decorator(func):
        async def wrapper(interaction: discord.Interaction, *args, **kwargs):
            if not rbac.has_permission(interaction.user.id, role):
                await interaction.response.send_message(
                    f"❌ **Access Denied**: You need '{role}' permission or higher.",
                    ephemeral=True
                )
                log_command(str(interaction.user), func.name, "DENIED")
                return
            return await func(interaction, *args, **kwargs)
        return wrapper
    return decorator

# ======================== COMMANDS ========================

@bot.event
async def on_ready():
    print(f'✅ Bot logged in as {bot.user}')
    print(f'📊 Loaded {len(rbac.users)} user records')
    try:
        synced = await bot.tree.sync()
        print(f'✅ Synced {len(synced)} commands')
    except Exception as e:
        print(f'❌ Failed to sync commands: {e}')

# ======================== ADMIN COMMANDS ========================
@bot.tree.command(name="admin", description="Manage user permissions (Admin only)")
@app_commands.describe(
    action="Action to perform: add, remove, list",
    user="User to manage",
    role="Role to assign: admin, user, readonly"
)
async def admin_cmd(interaction: discord.Interaction, action: str, user: Optional[discord.User] = None, role: Optional[str] = None):
    if not rbac.has_permission(interaction.user.id, 'admin'):
        await interaction.response.send_message("❌ Admin access required", ephemeral=True)
        return
    
    action = action.lower()
    
    if action == "list":
        users_data = rbac.list_users()
        embed = discord.Embed(title="👥 User Permissions", color=discord.Color.blue())
        
        for role_type in ['admins', 'users', 'readonly']:
            users_list = users_data.get(role_type, [])
            if users_list:
                embed.add_field(
                    name=f"🔹 {role_type.title()}",
                    value="\n".join([f"<@{uid}>" for uid in users_list]) or "None",
                    inline=False
                )
        
        await interaction.response.send_message(embed=embed)
        log_command(str(interaction.user), f"admin list", "SUCCESS")
    
    elif action == "add":
        if not user or not role:
            await interaction.response.send_message("❌ Please specify user and role", ephemeral=True)
            return
        
        if rbac.add_user(user.id, role):
            await interaction.response.send_message(f"✅ Added {user.mention} as **{role}**")
            log_command(str(interaction.user), f"admin add {user.name} as {role}", "SUCCESS")
        else:
            await interaction.response.send_message(f"❌ Invalid role. Use: admin, user, readonly", ephemeral=True)
    
    elif action == "remove":
        if not user:
            await interaction.response.send_message("❌ Please specify user", ephemeral=True)
            return
        
        if rbac.remove_user(user.id):
            await interaction.response.send_message(f"✅ Removed {user.mention} from all roles")
            log_command(str(interaction.user), f"admin remove {user.name}", "SUCCESS")
        else:
            await interaction.response.send_message(f"❌ User not found", ephemeral=True)

# ======================== FILE SYSTEM COMMANDS ========================
@bot.tree.command(name="ls", description="List directory contents")
@app_commands.describe(path="Path to list (default: current directory)")
async def ls_cmd(interaction: discord.Interaction, path: str = "."):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        items = os.listdir(path)
        output = "\n".join(items) if items else "Empty directory"
        
        if len(output) > 1900:
            output = output[:1900] + "\n... (truncated)"
        
        await interaction.response.send_message(f"📁 **Contents of `{path}`:**\n```\n{output}\n```")
        log_command(str(interaction.user), f"ls {path}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"ls {path}", "FAILED")

@bot.tree.command(name="pwd", description="Print working directory")
async def pwd_cmd(interaction: discord.Interaction):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    cwd = os.getcwd()
    await interaction.response.send_message(f"📂 **Current directory:**\n```\n{cwd}\n```")
    log_command(str(interaction.user), "pwd", "SUCCESS")

@bot.tree.command(name="cd", description="Change directory")
@app_commands.describe(path="Path to change to")
async def cd_cmd(interaction: discord.Interaction, path: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        os.chdir(path)
        new_path = os.getcwd()
        await interaction.response.send_message(f"✅ Changed directory to:\n```\n{new_path}\n```")
        log_command(str(interaction.user), f"cd {path}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"cd {path}", "FAILED")

@bot.tree.command(name="cat", description="Display file contents")
@app_commands.describe(filepath="Path to file")
async def cat_cmd(interaction: discord.Interaction, filepath: str):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read(3000)
        
        if len(content) > 1900:
            content = content[:1900] + "\n... (truncated)"
        
        await interaction.response.send_message(f"📄 **File: `{filepath}`**\n```\n{content}\n```")
        log_command(str(interaction.user), f"cat {filepath}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"cat {filepath}", "FAILED")

@bot.tree.command(name="write", description="Write content to file (overwrites)")
@app_commands.describe(filepath="Path to file", content="Content to write")
async def write_cmd(interaction: discord.Interaction, filepath: str, content: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        await interaction.response.send_message(f"✅ Written to `{filepath}`")
        log_command(str(interaction.user), f"write {filepath}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"write {filepath}", "FAILED")

@bot.tree.command(name="append", description="Append content to file")
@app_commands.describe(filepath="Path to file", content="Content to append")
async def append_cmd(interaction: discord.Interaction, filepath: str, content: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(content)
        
        await interaction.response.send_message(f"✅ Appended to `{filepath}`")
        log_command(str(interaction.user), f"append {filepath}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"append {filepath}", "FAILED")

@bot.tree.command(name="delete", description="Delete file or directory")
@app_commands.describe(path="Path to delete")
async def delete_cmd(interaction: discord.Interaction, path: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        else:
            await interaction.response.send_message(f"❌ Path not found: {path}", ephemeral=True)
            return
        
        await interaction.response.send_message(f"✅ Deleted `{path}`")
        log_command(str(interaction.user), f"delete {path}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"delete {path}", "FAILED")

@bot.tree.command(name="download", description="Download file from host")
@app_commands.describe(filepath="Path to file to download")
async def download_cmd(interaction: discord.Interaction, filepath: str):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        if not os.path.isfile(filepath):
            await interaction.response.send_message(f"❌ File not found: {filepath}", ephemeral=True)
            return
        
        file_size = os.path.getsize(filepath)
        if file_size > 25_000_000:  # 25MB Discord limit
            await interaction.response.send_message(f"❌ File too large ({file_size / 1_000_000:.1f}MB). Use /zip for large files.", ephemeral=True)
            return
        
        await interaction.response.send_message(f"📥 Uploading `{filepath}`...")
        await interaction.followup.send(file=discord.File(filepath))
        log_command(str(interaction.user), f"download {filepath}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"download {filepath}", "FAILED")

@bot.tree.command(name="zip", description="Create and download a zip of file/folder")
@app_commands.describe(path="Path to zip", zipname="Name for zip file")
async def zip_cmd(interaction: discord.Interaction, path: str, zipname: str = "archive.zip"):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        await interaction.response.defer()
        
        if not os.path.exists(path):
            await interaction.followup.send(f"❌ Path not found: {path}")
            return
        
        with zipfile.ZipFile(zipname, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isfile(path):
                zipf.write(path, os.path.basename(path))
            else:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.relpath(file_path, path))
        
        file_size = os.path.getsize(zipname)
        if file_size > 25_000_000:
            os.remove(zipname)
            await interaction.followup.send(f"❌ Zip too large ({file_size / 1_000_000:.1f}MB)")
            return
        
        await interaction.followup.send(f"📦 **Zipped: `{path}`**", file=discord.File(zipname))
        os.remove(zipname)
        log_command(str(interaction.user), f"zip {path}", "SUCCESS")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")
        log_command(str(interaction.user), f"zip {path}", "FAILED")

@bot.tree.command(name="upload", description="Upload file to host")
@app_commands.describe(attachment="File to upload", destination="Destination path (optional)")
async def upload_cmd(interaction: discord.Interaction, attachment: discord.Attachment, destination: Optional[str] = None):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        filepath = destination or attachment.filename
        await attachment.save(filepath)
        
        await interaction.response.send_message(f"✅ Uploaded to `{filepath}`")
        log_command(str(interaction.user), f"upload {filepath}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"upload {filepath}", "FAILED")

@bot.tree.command(name="get", description="Download file from the internet")
@app_commands.describe(url="URL to download", filename="Save as (optional)")
async def get_cmd(interaction: discord.Interaction, url: str, filename: Optional[str] = None):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        await interaction.response.defer()
        
        filename = filename or url.split('/')[-1] or 'downloaded_file'
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    await interaction.followup.send(f"❌ Failed to download: HTTP {resp.status}")
                    return
                
                with open(filename, 'wb') as f:
                    f.write(await resp.read())
        
        file_size = os.path.getsize(filename)
        await interaction.followup.send(f"✅ Downloaded `{filename}` ({file_size / 1024:.1f} KB)")
        log_command(str(interaction.user), f"get {url}", "SUCCESS")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")
        log_command(str(interaction.user), f"get {url}", "FAILED")

# ======================== SYSTEM COMMANDS ========================
@bot.tree.command(name="sh", description="Execute bash command")
@app_commands.describe(command="Bash command to execute")
async def sh_cmd(interaction: discord.Interaction, command: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr
        if not output:
            output = "✅ Command executed (no output)"
        
        if len(output) > 1900:
            output = output[:1900] + "\n... (truncated)"
        
        await interaction.response.send_message(f"```bash\n$ {command}\n\n{output}\n```")
        log_command(str(interaction.user), f"sh {command}", "SUCCESS")
    except subprocess.TimeoutExpired:
        await send_error(interaction, "Command timed out (30s limit)")
        log_command(str(interaction.user), f"sh {command}", "TIMEOUT")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"sh {command}", "FAILED")

@bot.tree.command(name="cmd", description="Execute any system command")
@app_commands.describe(command="Command to execute")
async def cmd_cmd(interaction: discord.Interaction, command: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr
        if not output:
            output = "✅ Command executed (no output)"
        
        if len(output) > 1900:
            output = output[:1900] + "\n... (truncated)"
        
        await interaction.response.send_message(f"```\n$ {command}\n\n{output}\n```")
        log_command(str(interaction.user), f"cmd {command}", "SUCCESS")
    except subprocess.TimeoutExpired:
        await send_error(interaction, "Command timed out (30s limit)")
        log_command(str(interaction.user), f"cmd {command}", "TIMEOUT")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"cmd {command}", "FAILED")

@bot.tree.command(name="python", description="Execute Python code or run Python file")
@app_commands.describe(code="Python code to execute or path to .py file")
async def python_cmd(interaction: discord.Interaction, code: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        # Check if it's a file path
        if code.endswith('.py') and os.path.isfile(code):
            result = subprocess.run(
                [sys.executable, code],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
        else:
            # Execute as code
            result = subprocess.run(
                [sys.executable, '-c', code],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
        
        if not output:
            output = "✅ Executed (no output)"
        
        if len(output) > 1900:
            output = output[:1900] + "\n... (truncated)"
        
        await interaction.response.send_message(f"```python\n{output}\n```")
        log_command(str(interaction.user), f"python", "SUCCESS")
    except subprocess.TimeoutExpired:
        await send_error(interaction, "Execution timed out (30s limit)")
        log_command(str(interaction.user), f"python", "TIMEOUT")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"python", "FAILED")

@bot.tree.command(name="ping", description="Ping URL or IP address")
@app_commands.describe(target="URL or IP to ping")
async def ping_cmd(interaction: discord.Interaction, target: str = "8.8.8.8"):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        # Detect OS and use appropriate ping command
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', target]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        output = result.stdout
        if len(output) > 1900:
            output = output[:1900] + "\n... (truncated)"
        
        await interaction.response.send_message(f"🏓 **Ping to `{target}`:**\n```\n{output}\n```")
        log_command(str(interaction.user), f"ping {target}", "SUCCESS")
    except subprocess.TimeoutExpired:
        await send_error(interaction, "Ping timed out")
        log_command(str(interaction.user), f"ping {target}", "TIMEOUT")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"ping {target}", "FAILED")

@bot.tree.command(name="disk", description="Show disk usage")
async def disk_cmd(interaction: discord.Interaction):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        disk = psutil.disk_usage('/')
        
        embed = discord.Embed(title="💾 Disk Usage", color=discord.Color.blue())
        embed.add_field(name="Total", value=f"{disk.total / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Used", value=f"{disk.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Free", value=f"{disk.free / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="Usage", value=f"{disk.percent}%", inline=True)
        
        await interaction.response.send_message(embed=embed)
        log_command(str(interaction.user), "disk", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), "disk", "FAILED")

@bot.tree.command(name="sys", description="Show system information")
async def sys_cmd(interaction: discord.Interaction):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        embed = discord.Embed(title="🖥️ System Information", color=discord.Color.green())
        embed.add_field(name="OS", value=f"{platform.system()} {platform.release()}", inline=False)
        embed.add_field(name="Python", value=platform.python_version(), inline=True)
        embed.add_field(name="CPU Usage", value=f"{cpu_percent}%", inline=True)
        embed.add_field(name="RAM Usage", value=f"{memory.percent}%", inline=True)
        embed.add_field(name="RAM Used", value=f"{memory.used / (1024**3):.2f} GB", inline=True)
        embed.add_field(name="RAM Total", value=f"{memory.total / (1024**3):.2f} GB", inline=True)
        
        await interaction.response.send_message(embed=embed)
        log_command(str(interaction.user), "sys", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), "sys", "FAILED")

@bot.tree.command(name="log", description="View recent command logs")
@app_commands.describe(lines="Number of log lines to show (default: 20)")
async def log_cmd(interaction: discord.Interaction, lines: int = 20):
    if not rbac.has_permission(interaction.user.id, 'admin'):
        await interaction.response.send_message("❌ Admin access required", ephemeral=True)
        return
    
    await interaction.response.send_message(f"📋 **Last {lines} log entries:**\n```\nCheck your console/terminal for logs\n```")
    log_command(str(interaction.user), f"log {lines}", "SUCCESS")

# ======================== RUN BOT ========================
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("❌ DISCORD_TOKEN not set in environment variables")
        exit(1)
    
    if not JSONBIN_API_KEY or not JSONBIN_BIN_ID:
        print("⚠️ JSONBin credentials not set. User management will not persist!")
    
    print("🚀 Starting Discord Remote Management Bot...")
    print("=" * 50)
    bot.run(DISCORD_TOKEN)
