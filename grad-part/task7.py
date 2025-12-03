import base64
import json
import os
import re
import subprocess
import tempfile
from urllib.parse import urlparse

import pandas as pd
import requests


def is_python_file(filename):
    """
    Check if a file is a Python file based on its extension.
    """
    if pd.isna(filename) or not isinstance(filename, str):
        return False

    python_extensions = [".py", ".pyw", ".pyi"]
    return any(filename.lower().endswith(ext) for ext in python_extensions)


def extract_repo_info_from_url(repo_url):
    """
    Extract owner and repository name from GitHub API URL
    """
    if pd.isna(repo_url) or not isinstance(repo_url, str):
        return None, None

    try:
        # Handle GitHub API URLs
        if "api.github.com/repos/" in repo_url:
            parts = repo_url.split("/repos/")[-1].split("/")
            if len(parts) >= 2:
                return parts[0], parts[1]
        return None, None
    except Exception:
        return None, None


def get_file_content_from_github(owner, repo, filepath, sha=None):
    """
    Fetch file content from GitHub repository using the GitHub API
    """
    if not owner or not repo or not filepath:
        return None

    try:
        filepath = filepath.lstrip("./")

        # Construct GitHub API URL
        if sha:
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}?ref={sha}"
        else:
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}"

        # Make request
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Python-Security-Scanner",
        }

        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get("encoding") == "base64":
                content = base64.b64decode(data["content"]).decode("utf-8")
                return content

        return None

    except Exception as e:
        print(f"Error fetching file {filepath}: {e}")
        return None


def scan_python_code_with_bandit(code_content, filename="temp.py"):
    """
    Scan Python code content using Bandit and return vulnerability count.
    """
    if not code_content or not isinstance(code_content, str):
        return 0

    try:
        # Create temporary file with the code content
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as temp_file:
            temp_file.write(code_content)
            temp_file_path = temp_file.name

        try:
            # Run Bandit scan with JSON output
            cmd = ["bandit", "-f", "json", "-q", temp_file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Parse Bandit JSON output
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    results = bandit_data.get("results", [])

                    # Count unique vulnerabilities
                    vulnerability_count = len(results)
                    return vulnerability_count

                except json.JSONDecodeError:
                    return 0

            return 0

        finally:
            # Clean up temporary file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    except Exception as e:
        print(f"Error scanning code with Bandit: {e}")
        return 0


def check_bandit_availability():
    """
    Check if Bandit is available in the system.
    """
    try:
        result = subprocess.run(["bandit", "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def process_vulnerabilities_for_commits(task4_df, batch_size=50):
    """
    Process commit data to check for vulnerabilities in Python files
    """
    print("Processing vulnerability scanning for Python files")

    # Check if Bandit is available
    if not check_bandit_availability():
        print("ERROR: Bandit is not installed or not available in PATH")
        print("Please install Bandit: pip install bandit")
        return None

    # Load repository data for URL mapping
    repo_file = os.path.join("output", "task2_repositories.csv")
    repo_mapping = {}

    if os.path.exists(repo_file):
        repo_df = pd.read_csv(repo_file)
        repo_df["REPOID"] = repo_df["REPOID"].astype(str)

        for _, row in repo_df.iterrows():
            owner, repo = extract_repo_info_from_url(row["REPOURL"])
            if owner and repo:
                repo_mapping[str(row["REPOID"])] = (owner, repo)

        print(f"Loaded {len(repo_mapping)} repository mappings")
    else:
        print("Task 2 repository data not found")

    # Initialize vulnerability column
    vulnerabilities = []

    total_files = len(task4_df)
    python_files_count = 0
    scanned_files_count = 0
    vulnerable_files_count = 0

    print(f"Processing {total_files} commit file records...")

    for index, row in task4_df.iterrows():
        is_vulnerable = 0

        # Progress indicator
        if index % 1000 == 0:
            print(f"Progress: {index}/{total_files} ({index / total_files * 100:.1f}%)")

        filename = row.get("PRFILE", "")

        # Check if it's a Python file
        if is_python_file(filename):
            python_files_count += 1

            # Try to get repository information
            repo_id = str(row.get("PRID", ""))  # Using PRID as repo identifier

            # Use the patch/diff content
            # as a proxy for file content since accessing all repositories
            # would be rate-limited and time-consuming

            patch_content = row.get("PRDIFF", "")

            if patch_content and isinstance(patch_content, str):
                # Extract added lines from the diff (lines starting with +)
                # This represents the Python code being added/modified
                added_lines = []
                for line in patch_content.split("\n"):
                    if line.startswith("+") and not line.startswith("+++"):
                        # Remove the + prefix and add to code content
                        added_lines.append(line[1:])

                if added_lines:
                    # Create Python code from added lines
                    code_content = "\n".join(added_lines)

                    # Only scan if we have substantial Python code content
                    if len(code_content.strip()) > 50:  # Minimum threshold
                        scanned_files_count += 1

                        # Scan with Bandit
                        vulnerability_count = scan_python_code_with_bandit(
                            code_content, filename
                        )

                        if vulnerability_count > 0:
                            is_vulnerable = 1
                            vulnerable_files_count += 1

        vulnerabilities.append(is_vulnerable)

    print(f"\nScanning Summary:")
    print(f"Total files processed: {total_files}")
    print(f"Python files identified: {python_files_count}")
    print(f"Python files scanned: {scanned_files_count}")
    print(f"Vulnerable Python files found: {vulnerable_files_count}")

    return vulnerabilities


def create_task7_with_vulnerability_scan():
    """
    Create Task 7 output by adding VULNERABLEFILE column to Task 4 data.
    """
    print("Starting Task 7: Vulnerability Scanning Analysis")
    print("=" * 60)

    try:
        # Load Task 4 data
        task4_file = os.path.join("output", "task4_pr_commit_details.csv")

        if not os.path.exists(task4_file):
            print(f"ERROR: Task 4 file not found: {task4_file}")
            print("Please run Task 4 first to generate the required data.")
            return None

        print(f"Loading commit details from: {task4_file}")
        task4_df = pd.read_csv(task4_file)

        # Check if this is a Git LFS pointer file
        if len(task4_df) < 1000 or "version" in str(task4_df.iloc[0, 0]):
            print("Task 4 file appears to be a Git LFS pointer. Regenerating data...")
            task4_df = regenerate_task4_data()
            if task4_df is None:
                return None

        print(f"Loaded {len(task4_df)} commit detail records")

        # Process vulnerability scanning
        vulnerabilities = process_vulnerabilities_for_commits(task4_df)

        if vulnerabilities is None:
            print("Vulnerability scanning failed. Cannot complete Task 7.")
            return None

        # Add VULNERABLEFILE column
        task4_df["VULNERABLEFILE"] = vulnerabilities

        # Create Task 7 output with all required columns
        task7_columns = [
            "PRID",
            "PRSHA",
            "PRCOMMITMESSAGE",
            "PRFILE",
            "PRSTATUS",
            "PRADDS",
            "PRDELSS",
            "PRCHANGECOUNT",
            "PRDIFF",
            "VULNERABLEFILE",
        ]

        task7_df = task4_df[task7_columns].copy()

        # Save Task 7 output
        output_file = os.path.join("output", "task7_pr_vulnerability_scan.csv")
        task7_df.to_csv(output_file, index=False)

        print(f"\nTask 7 completed successfully!")
        print(f"Output saved to: {output_file}")
        print(f"Total records: {len(task7_df)}")

        # Display vulnerability statistics
        vulnerable_files = task7_df[task7_df["VULNERABLEFILE"] == 1]
        print(f"Vulnerable files identified: {len(vulnerable_files)}")

        if len(vulnerable_files) > 0:
            print(
                f"Vulnerability rate: {len(vulnerable_files) / len(task7_df) * 100:.2f}%"
            )

            # Show top file types with vulnerabilities
            if len(vulnerable_files) > 0:
                print("\nTop vulnerable file patterns:")
                file_patterns = (
                    vulnerable_files["PRFILE"]
                    .apply(lambda x: x.split("/")[-1] if pd.notna(x) else "unknown")
                    .value_counts()
                    .head(10)
                )

                for pattern, count in file_patterns.items():
                    print(f"  {pattern}: {count}")

        return task7_df

    except Exception as e:
        print(f"Error in Task 7 processing: {e}")
        return None


def clean_patch_content(patch_text):
    """
    Clean patch content by removing special characters that could cause encoding errors
    while preserving the essential diff structure.
    """
    if pd.isna(patch_text) or patch_text is None:
        return ""

    # Convert to string if not already
    patch_str = str(patch_text)

    # Remove or replace problematic special characters
    # Keep basic diff symbols but remove other special characters
    patch_str = re.sub(
        r"[^\x20-\x7E\n\r\t]", "", patch_str
    )  # Keep only printable ASCII + whitespace

    # Additional cleanup for common problematic sequences
    patch_str = patch_str.replace("\x00", "")  # Remove null bytes
    patch_str = patch_str.replace("\ufeff", "")  # Remove BOM

    return patch_str


def regenerate_task4_data():
    """
    Regenerate Task 4 data if the file is a Git LFS pointer.
    """
    try:
        print("Loading PR commit details data")
        df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_commit_details.parquet")

        print(f"Loaded {len(df)} PR commit detail records")
        print(f"Available columns: {list(df.columns)}")

        print("Cleaning patch data to remove special characters")
        cleaned_patches = df["patch"].apply(clean_patch_content)

        task4_df = pd.DataFrame(
            {
                "PRID": df["pr_id"],
                "PRSHA": df["sha"],
                "PRCOMMITMESSAGE": df["message"],
                "PRFILE": df["filename"],
                "PRSTATUS": df["status"],
                "PRADDS": df["additions"],
                "PRDELSS": df["deletions"],
                "PRCHANGECOUNT": df["changes"],
                "PRDIFF": cleaned_patches,
            }
        )

        print(f"Regenerated Task 4")
        return task4_df

    except Exception as e:
        print(f"Error regenerating Task 4 data: {e}")
        return None


def install_bandit_if_missing():
    """
    Helper function to install Bandit
    """
    if not check_bandit_availability():
        print("Bandit not found. Attempting to install")
        try:
            subprocess.run(["pip", "install", "bandit"], check=True)
            print("Bandit installed")
            return True
        except subprocess.CalledProcessError:
            print("Failed to install Bandit")
            return False
    return True


def main():
    print("Task 7: Python File Vulnerability Scanning with Bandit")
    print("=" * 60)

    # Check/install Bandit
    if not install_bandit_if_missing():
        print("Cannot proceed without Bandit. Exiting.")
        return

    # Execute Task 7
    result = create_task7_with_vulnerability_scan()

    if result is not None:
        print("\nTask 7 execution completed")
    else:
        print("\nTask 7 execution failed")


if __name__ == "__main__":
    main()
