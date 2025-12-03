import os
import re

import pandas as pd


def clean_patch(patch_text):
    """
    Clean data related to patch by removing special characters in the diff
    """
    if pd.isna(patch_text) or patch_text is None:
        return ""

    patch_str = str(patch_text)

    # Keep basic diff symbols but remove other special characters
    patch_str = re.sub(r"[^\x20-\x7E\n\r\t]", "", patch_str)

    # Additional replacements
    patch_str = patch_str.replace("\x00", "")  # Remove null bytes
    patch_str = patch_str.replace("\ufeff", "")  # Remove BOM

    return patch_str


def task4_process_pr_commit_details():
    """
    Task 4: Process pr_commit_details data and create CSV with specific column mappings
    """

    try:
        print("Loading PR commit details from Hugging Face dataset...")

        df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_commit_details.parquet")

        print("Removing special characters from patch")

        # Remove special characters
        cleaned_patches = df["patch"].apply(clean_patch)

        # Create the new dataframe with the column mappings
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

        # Create output directory if it doesn't exist
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save to CSV file
        output_file = os.path.join(output_dir, "task4_pr_commit_details.csv")
        task4_df.to_csv(output_file, index=False, encoding="utf-8")

        print("Task 4 completed successfully")
        print(f"Output saved to: {output_file}")
        print(f"Number of records processed: {len(task4_df)}")

        return task4_df

    except Exception as e:
        print(f"Error processing Task 4: {str(e)}")
        return None


if __name__ == "__main__":
    print("Processing PR Commit Details Data")
    print("=" * 50)

    # Run Task 4
    result = task4_process_pr_commit_details()

    if result is not None:
        print("\nTask 4 execution completed")
    else:
        print("\nTask 4 execution failed")
