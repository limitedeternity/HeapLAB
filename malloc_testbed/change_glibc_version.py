#!/usr/bin/python3
import os

# Grab available GLIBC versions.
available_versions = []
for item in os.scandir("../.glibc"):
    if item.is_dir():
        available_versions.append(item)
available_versions.sort(key=lambda x:x.name)

# Print menu.
print("\n--------------------")
print("Select GLIBC version")
print("--------------------")
for c, version in enumerate(available_versions):
    print(f"{c:02}) " + version.name)

# Process input.
choice = int(input("> "))
if choice < len(available_versions):
    # Remove old symlinks.
    try:
        os.unlink(".links/libc.so.6")
        os.unlink(".links/ld.so.2")
    except FileNotFoundError:
        print("No old links to remove")

    # Replace symlinks.
    os.symlink("../" + available_versions[choice].path + "/libc.so.6", ".links/libc.so.6")
    os.symlink("../" + available_versions[choice].path + "/ld.so.2", ".links/ld.so.2")
