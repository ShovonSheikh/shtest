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
from aiohttp import web
import threading
import shlex
import signal

# ======================== RENDER CONFIGURATION ========================
# Render provides PORT environment variable dynamically
PORT = int(os.getenv('PORT', 4853))

# ======================== CONFIGURATION ========================
# Load secrets from environment variables. Do NOT keep secrets in source.
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
JSONBIN_API_KEY = os.getenv('JSONBIN_API_KEY')
JSONBIN_BIN_ID = os.getenv('JSONBIN_BIN_ID')

# ======================== PROCESS TRACKING ========================
active_processes = {}
process_counter = 0

def get_next_process_id():
    global process_counter
    process_counter += 1
    return process_counter

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
    async def get_users(self):
        """Fetch user data from JSONBin (async)"""
        if not self.api_key or not self.bin_id:
            return {}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/latest", headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('record', {})
                    return {}
        except Exception as e:
            print(f"Error fetching users: {e}")
            return {}

    async def save_users(self, users_data):
        """Save user data to JSONBin (async)"""
        if not self.api_key or not self.bin_id:
            return False

        try:
            async with aiohttp.ClientSession() as session:
                async with session.put(self.base_url, json=users_data, headers=self.headers) as resp:
                    return resp.status == 200
        except Exception as e:
            print(f"Error saving users: {e}")
            return False

# ======================== RBAC SYSTEM ========================
class RBACSystem:
    ROLES = ['admin', 'user', 'readonly']
    
    def __init__(self, storage):
        self.storage = storage
        # Start with a default in-memory structure; load persisted data asynchronously
        self.users = {'admins': [], 'users': [], 'readonly': []}

    async def load_users(self):
        """Load users from storage asynchronously and initialize defaults if needed."""
        try:
            users = await self.storage.get_users()
            if users:
                self.users = users
            else:
                # Ensure structure exists in storage
                await self.storage.save_users(self.users)
        except Exception as e:
            print(f"Error loading RBAC users: {e}")
    
    async def add_user(self, user_id: int, role: str):
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
            await self.storage.save_users(self.users)

        return True
    
    async def remove_user(self, user_id: int):
        """Remove user from all roles"""
        user_id = str(user_id)
        removed = False
        
        for role in self.ROLES:
            key = f"{role}s"
            if user_id in self.users.get(key, []):
                self.users[key].remove(user_id)
                removed = True
        
        if removed:
            await self.storage.save_users(self.users)

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
intents.message_content = True  # Only enable message content intent

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
    # Try primary response; if the interaction was deferred or responded to already,
    # fall back to followup. This prevents runtime errors after `defer()`.
    try:
        await ctx.response.send_message(f"❌ **Error:**\n```\n{error_msg}\n```", ephemeral=True)
    except Exception:
        try:
            await ctx.followup.send(f"❌ **Error:**\n```\n{error_msg}\n```", ephemeral=True)
        except Exception:
            # Give up gracefully but keep the error visible in logs
            print("Failed to send error to Discord interaction.")

# ======================== STREAMING COMMAND EXECUTOR ========================
async def stream_command_output(interaction: discord.Interaction, args: list, command_str: str, shell_type: str = "bash"):
    """
    Execute a command and stream its output in real-time by editing the Discord message.
    
    Args:
        interaction: Discord interaction object
        args: Command arguments list (for subprocess)
        command_str: Original command string (for display)
        shell_type: Type of shell for formatting ("bash", "python", or "plain")
    """
    proc_id = get_next_process_id()
    start_time = datetime.now()
    
    try:
        # Start the process
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Track the process
        active_processes[proc_id] = {
            'proc': proc,
            'command': command_str,
            'user': interaction.user,
            'start_time': start_time,
            'interaction': interaction
        }
        
        output_buffer = ""
        last_update = datetime.now()
        update_interval = 0.5  # Update every 0.5 seconds
        
        # Send initial message
        shell_format = shell_type if shell_type in ["bash", "python"] else ""
        initial_msg = f"🔄 **Running...** (Process #{proc_id})\n\n```{shell_format}\n$ {command_str}\n\n```"
        message = await interaction.followup.send(initial_msg)
        
        async def read_stream(stream, prefix=""):
            """Read from stream and return output"""
            nonlocal output_buffer
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode('utf-8', errors='replace')
                    output_buffer += prefix + decoded
            except Exception as e:
                output_buffer += f"\n[Stream error: {e}]"
        
        # Create tasks to read both stdout and stderr
        stdout_task = asyncio.create_task(read_stream(proc.stdout))
        stderr_task = asyncio.create_task(read_stream(proc.stderr, ""))
        
        # Monitor the process and update message
        while proc.returncode is None:
            # Check if process is still running
            try:
                await asyncio.wait_for(proc.wait(), timeout=0.1)
            except asyncio.TimeoutError:
                pass
            
            # Update message periodically
            now = datetime.now()
            if (now - last_update).total_seconds() >= update_interval:
                elapsed = (now - start_time).total_seconds()
                
                # Prepare output (truncate if too long)
                display_output = output_buffer
                if len(display_output) > 1800:
                    # Show last 1800 chars
                    display_output = "... (truncated)\n" + display_output[-1800:]
                
                status_msg = f"🔄 **Running...** (Process #{proc_id} | {elapsed:.1f}s)\n\n```{shell_format}\n$ {command_str}\n\n{display_output}```"
                
                try:
                    await message.edit(content=status_msg)
                    last_update = now
                except discord.errors.HTTPException:
                    # Rate limit or other issue, skip this update
                    pass
            
            await asyncio.sleep(0.1)
        
        # Wait for stream reading to complete
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        
        # Process completed - send final message
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if not output_buffer:
            output_buffer = "(no output)"
        
        # Prepare final output
        final_output = output_buffer
        if len(final_output) > 1800:
            final_output = "... (truncated)\n" + final_output[-1800:]
        
        if proc.returncode == 0:
            status_icon = "✅"
            status_text = "Completed"
        else:
            status_icon = "❌"
            status_text = f"Failed (exit code: {proc.returncode})"
        
        final_msg = f"{status_icon} **{status_text}** (Process #{proc_id} | {elapsed:.1f}s)\n\n```{shell_format}\n$ {command_str}\n\n{final_output}```"
        
        try:
            await message.edit(content=final_msg)
        except discord.errors.HTTPException:
            # If edit fails, send new message
            await interaction.followup.send(final_msg)
        
        return proc.returncode
        
    except Exception as e:
        error_msg = f"❌ **Execution Error** (Process #{proc_id})\n```\n{str(e)}\n```"
        try:
            await interaction.followup.send(error_msg)
        except:
            pass
        return -1
    finally:
        # Clean up process tracking
        if proc_id in active_processes:
            del active_processes[proc_id]

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
    print(f'📊 RBAC in-memory records: {len(rbac.users)}')

    # Start web server
    asyncio.create_task(start_webserver())

    # Load persisted RBAC users asynchronously
    try:
        await rbac.load_users()
        print(f'📊 Loaded {len(rbac.users)} user records from storage')
    except Exception as e:
        print(f'⚠️ Failed to load RBAC users: {e}')

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
        if await rbac.add_user(user.id, role):
            await interaction.response.send_message(f"✅ Added {user.mention} as **{role}**")
            log_command(str(interaction.user), f"admin add {user.name} as {role}", "SUCCESS")
        else:
            await interaction.response.send_message(f"❌ Invalid role. Use: admin, user, readonly", ephemeral=True)
    
    elif action == "remove":
        if not user:
            await interaction.response.send_message("❌ Please specify user", ephemeral=True)
            return
        if await rbac.remove_user(user.id):
            await interaction.response.send_message(f"✅ Removed {user.mention} from all roles")
            log_command(str(interaction.user), f"admin remove {user.name}", "SUCCESS")
        else:
            await interaction.response.send_message(f"❌ User not found", ephemeral=True)

# ======================== PROCESS CONTROL COMMANDS ========================
@bot.tree.command(name="ps", description="List active processes")
async def ps_cmd(interaction: discord.Interaction):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    if not active_processes:
        await interaction.response.send_message("📋 No active processes", ephemeral=True)
        return
    
    embed = discord.Embed(title="📋 Active Processes", color=discord.Color.blue())
    
    for proc_id, proc_info in active_processes.items():
        elapsed = (datetime.now() - proc_info['start_time']).total_seconds()
        user_mention = proc_info['user'].mention
        command = proc_info['command']
        
        # Truncate long commands
        if len(command) > 50:
            command = command[:47] + "..."
        
        field_value = f"**User:** {user_mention}\n**Command:** `{command}`\n**Runtime:** {elapsed:.1f}s\n**Control:** `/stop {proc_id}` or `/kill {proc_id}`"
        
        embed.add_field(
            name=f"🔹 Process #{proc_id}",
            value=field_value,
            inline=False
        )
    
    await interaction.response.send_message(embed=embed)
    log_command(str(interaction.user), "ps", "SUCCESS")

@bot.tree.command(name="stop", description="Stop a running process (SIGTERM)")
@app_commands.describe(process_id="Process ID to stop")
async def stop_cmd(interaction: discord.Interaction, process_id: int):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    if process_id not in active_processes:
        await interaction.response.send_message(f"❌ Process #{process_id} not found", ephemeral=True)
        return
    
    proc_info = active_processes[process_id]
    
    # Check if user owns the process or is admin
    is_admin = rbac.has_permission(interaction.user.id, 'admin')
    is_owner = proc_info['user'].id == interaction.user.id
    
    if not (is_admin or is_owner):
        await interaction.response.send_message("❌ You can only stop your own processes", ephemeral=True)
        return
    
    try:
        proc = proc_info['proc']
        
        # Send SIGTERM for graceful shutdown
        if platform.system() == "Windows":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGTERM)
        
        await interaction.response.send_message(f"✅ Sent stop signal (SIGTERM) to process #{process_id}")
        log_command(str(interaction.user), f"stop {process_id}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, f"Failed to stop process: {str(e)}")
        log_command(str(interaction.user), f"stop {process_id}", "FAILED")

@bot.tree.command(name="kill", description="Force kill a process (SIGKILL)")
@app_commands.describe(process_id="Process ID to kill")
async def kill_cmd(interaction: discord.Interaction, process_id: int):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    if process_id not in active_processes:
        await interaction.response.send_message(f"❌ Process #{process_id} not found", ephemeral=True)
        return
    
    proc_info = active_processes[process_id]
    
    # Check if user owns the process or is admin
    is_admin = rbac.has_permission(interaction.user.id, 'admin')
    is_owner = proc_info['user'].id == interaction.user.id
    
    if not (is_admin or is_owner):
        await interaction.response.send_message("❌ You can only kill your own processes", ephemeral=True)
        return
    
    try:
        proc = proc_info['proc']
        
        # Send SIGKILL for immediate termination
        proc.kill()
        
        await interaction.response.send_message(f"✅ Force killed process #{process_id}")
        log_command(str(interaction.user), f"kill {process_id}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, f"Failed to kill process: {str(e)}")
        log_command(str(interaction.user), f"kill {process_id}", "FAILED")

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
        await interaction.response.defer()

        if not os.path.isfile(filepath):
            await interaction.followup.send(f"❌ File not found: {filepath}", ephemeral=True)
            return

        file_size = os.path.getsize(filepath)
        if file_size > 25_000_000:  # 25MB Discord limit
            await interaction.followup.send(f"❌ File too large ({file_size / 1_000_000:.1f}MB). Use /zip for large files.", ephemeral=True)
            return

        await interaction.followup.send(f"📥 Uploading `{filepath}`...")
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

        def _create_zip(pth, zname):
            with zipfile.ZipFile(zname, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if os.path.isfile(pth):
                    zipf.write(pth, os.path.basename(pth))
                else:
                    for root, dirs, files in os.walk(pth):
                        for file in files:
                            file_path = os.path.join(root, file)
                            zipf.write(file_path, os.path.relpath(file_path, pth))

        # Offload zipping to a thread to avoid blocking the event loop
        await asyncio.to_thread(_create_zip, path, zipname)

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

# ======================== SYSTEM COMMANDS WITH STREAMING ========================
@bot.tree.command(name="sh", description="Execute bash command with real-time output")
@app_commands.describe(command="Bash command to execute")
async def sh_cmd(interaction: discord.Interaction, command: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        await interaction.response.defer()
        args = shlex.split(command)
        await stream_command_output(interaction, args, command, "bash")
        log_command(str(interaction.user), f"sh {command}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"sh {command}", "FAILED")

@bot.tree.command(name="cmd", description="Execute system command with real-time output")
@app_commands.describe(command="Command to execute")
async def cmd_cmd(interaction: discord.Interaction, command: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        await interaction.response.defer()
        args = shlex.split(command)
        await stream_command_output(interaction, args, command, "plain")
        log_command(str(interaction.user), f"cmd {command}", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"cmd {command}", "FAILED")

@bot.tree.command(name="python", description="Execute Python code or file with real-time output")
@app_commands.describe(code="Python code to execute or path to .py file")
async def python_cmd(interaction: discord.Interaction, code: str):
    if not rbac.has_permission(interaction.user.id, 'user'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    try:
        await interaction.response.defer()
        
        if code.endswith('.py') and os.path.isfile(code):
            args = [sys.executable, code]
            display_cmd = f"python {code}"
        else:
            args = [sys.executable, '-c', code]
            display_cmd = code
        
        await stream_command_output(interaction, args, display_cmd, "python")
        log_command(str(interaction.user), f"python", "SUCCESS")
    except Exception as e:
        await send_error(interaction, str(e))
        log_command(str(interaction.user), f"python", "FAILED")

@bot.tree.command(name="ping", description="Check site latency via HTTP")
@app_commands.describe(target="URL to check (e.g., google.com)")
async def ping_cmd(interaction: discord.Interaction, target: str = "google.com"):
    if not rbac.has_permission(interaction.user.id, 'readonly'):
        await interaction.response.send_message("❌ Access denied", ephemeral=True)
        return
    
    if not target.startswith("http"):
        target = f"http://{target}"

    try:
        await interaction.response.defer()
        start = datetime.now()
        async with aiohttp.ClientSession() as session:
            async with session.get(target, timeout=5) as resp:
                latency = (datetime.now() - start).total_seconds() * 1000
                await interaction.followup.send(f"🏓 **Pong!**\nSite: `{target}`\nStatus: `{resp.status}`\nLatency: `{latency:.0f}ms`")
        log_command(str(interaction.user), f"ping {target}", "SUCCESS")
    except Exception as e:
        await interaction.followup.send(f"❌ Could not reach `{target}`: {str(e)}")
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

# ======================== WEB SERVER ========================
async def health_check(request):
    """Simple health check endpoint"""
    return web.Response(text="OK", status=200)

async def start_webserver():
    """Start simple web server on port specified by PORT env variable"""
    app = web.Application()
    app.router.add_get('/', health_check)
    app.router.add_get('/health', health_check)
    app.router.add_get('/status', health_check)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    print(f"✅ Web server running on http://0.0.0.0:{PORT}")

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
