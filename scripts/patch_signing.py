#!/usr/bin/env python3
import os
import glob
import re

print("Patching Xcode project for unsigned sideloading...")

for pbx in glob.glob("gen/apple/**/*.pbxproj", recursive=True):
    with open(pbx, "r") as f:
        txt = f.read()

    txt = txt.replace("CODE_SIGN_STYLE = Automatic;", "CODE_SIGN_STYLE = Manual;")
    txt = txt.replace("ProvisioningStyle = Automatic;", "ProvisioningStyle = Manual;")
    txt = re.sub(r'DevelopmentTeam = [^;]+;', 'DevelopmentTeam = "";', txt)
    txt = re.sub(r'PROVISIONING_PROFILE_SPECIFIER = [^;]+;', 'PROVISIONING_PROFILE_SPECIFIER = "";', txt)

    settings_replacement = """buildSettings = {
				CODE_SIGNING_ALLOWED = NO;
				CODE_SIGNING_REQUIRED = NO;
				CODE_SIGN_STYLE = Manual;
				CODE_SIGN_IDENTITY = "";
				PROVISIONING_PROFILE_SPECIFIER = "";"""
    txt = txt.replace("buildSettings = {", settings_replacement)

    with open(pbx, "w") as f:
        f.write(txt)
    print(f"Patched PBX: {pbx}")
