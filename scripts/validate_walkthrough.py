import os
import re
import sys

# Required headings as specified (including typos)
REQUIRED_STRUCTURE = [
    "## Binary foundataions",
    "### File identificaiton",
    "### architecrue and word size",
    "### stripped vs not stripped",
    "## secuirty mitigations",
    "## static analysis",
    "### cfg",
    "### decompilation",
    "### XREFS",
    "## Dynamic analysis",
    "### GDB",
    "### Tracing",
    "## Exploitation theory",
    "### Stack frame",
    "### ROP"
]

def validate_file(filepath):
    print(f"Validating: {filepath}")
    with open(filepath, 'r') as f:
        content = f.read()

    errors = []
    
    # Check for each heading and content following it
    for i, heading in enumerate(REQUIRED_STRUCTURE):
        # Escape for regex (some might have special chars, though here mostly safe)
        escaped_heading = re.escape(heading)
        
        # Regex to find the heading and everything until the next heading or end of file
        # We look for the exact heading at the start of a line
        pattern = rf"^{escaped_heading}\s*\n(.*?)(?=\n#|$)"
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        
        if not match:
            errors.append(f"Missing required heading: '{heading}'")
            continue
            
        section_content = match.group(1).strip()
        if not section_content:
            errors.append(f"Section '{heading}' is empty")

    return errors

def main():
    # Find all walkthrough.md files in the repository
    walkthrough_files = []
    for root, dirs, files in os.walk('.'):
        if 'walkthrough.md' in files:
            # Check if it's in a subdirectory (which would be the issue folder)
            if root != '.':
                walkthrough_files.append(os.path.join(root, 'walkthrough.md'))

    if not walkthrough_files:
        print("No walkthrough.md files found in subdirectories.")
        return

    all_errors = {}
    for filepath in walkthrough_files:
        errors = validate_file(filepath)
        if errors:
            all_errors[filepath] = errors

    if all_errors:
        print("\n❌ Validation Failed!")
        for filepath, errors in all_errors.items():
            print(f"\nErrors in {filepath}:")
            for error in errors:
                print(f"  - {error}")
        sys.exit(1)
    else:
        print("\n✅ All walkthrough files passed validation!")

if __name__ == "__main__":
    main()
