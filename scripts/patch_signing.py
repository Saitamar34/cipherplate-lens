#!/usr/bin/env python3
import os
import glob
import re

print("Patching Xcode project for ad-hoc / sideload signing...")

# 1. Patch project.yml if present
for yml in glob.glob("gen/apple/**/project.yml", recursive=True):
    with open(yml, "r") as f:
        content = f.read()
    
    # Add ad-hoc signing configuration to project.yml
    if "CODE_SIGN_STYLE" not in content:
        # append global settings override
        patch = """
settings:
  base:
    CODE_SIGN_STYLE: Manual
    CODE_SIGN_IDENTITY: "-"
    AD_HOC_CODE_SIGNING_ALLOWED: YES
    CODE_SIGNING_REQUIRED: NO
"""
        content += patch
        with open(yml, "w") as f:
            f.write(content)
        print(f"Patched YAML: {yml}")

# 2. Patch project.pbxproj directly
for pbx in glob.glob("gen/apple/**/*.pbxproj", recursive=True):
    with open(pbx, "r") as f:
        txt = f.read()

    txt = txt.replace("CODE_SIGN_STYLE = Automatic;", "CODE_SIGN_STYLE = Manual;")
    txt = txt.replace("ProvisioningStyle = Automatic;", "ProvisioningStyle = Manual;")
    txt = re.sub(r'DevelopmentTeam = [^;]+;', 'DevelopmentTeam = "";', txt)
    
    settings_replacement = """buildSettings = {
				CODE_SIGN_STYLE = Manual;
				CODE_SIGN_IDENTITY = "-";
				AD_HOC_CODE_SIGNING_ALLOWED = YES;
				CODE_SIGNING_REQUIRED = NO;"""
    txt = txt.replace("buildSettings = {", settings_replacement)

    with open(pbx, "w") as f:
        f.write(txt)
    print(f"Patched PBX: {pbx}")
