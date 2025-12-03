import os

import pandas as pd


def create_manual_security_validation():
    """
    Creates a dataset for manual security validation based on Task 5 results
    """

    output_path = "output"
    os.makedirs(output_path, exist_ok=True)

    # Load Task 5 security analysis results
    security_summary_path = os.path.join(output_path, "task5_pr_security_summary.csv")

    if not os.path.exists(security_summary_path):
        print(f"Security summary file missing at {security_summary_path}")
        print("Please execute Task 5 first")
        return None

    print(f"Reading security analysis from: {security_summary_path}")
    security_data = pd.read_csv(security_summary_path)

    print(f"Processing {len(security_data)} pull request records")

    # Initialize validation tracking column (default value 0)
    security_data["VALIDATED"] = 0

    # Extract only required columns for final output
    validation_columns = ["ID", "AGENT", "TYPE", "CONFIDENCE", "SECURITY", "VALIDATED"]
    final_dataset = security_data[validation_columns].copy()

    # Save primary validation file
    validation_output = os.path.join(output_path, "task6_pr_security_validated.csv")
    final_dataset.to_csv(validation_output, index=False)

    print(f"CSV with validation created: {validation_output}")
    print(f"Records in validation dataset: {len(final_dataset)}")

    # Count items needing manual review
    security_flagged_count = final_dataset[final_dataset["SECURITY"] == 1].shape[0]
    print(f"Pull requests requiring manual validation: {security_flagged_count}")

    create_review(security_data, output_path)

    return final_dataset


def create_review(security_data, output_path):
    """
    Creates CSV containing pull request content for manual validation
    """

    pr_details_path = os.path.join(output_path, "task1_pull_requests.csv")

    try:
        # Load pull request content
        print("Loading pull request content")

        pr_content = load_pr_content_data(pr_details_path)

        if pr_content is not None:
            # Ensure ID columns match for merging
            security_data["ID"] = security_data["ID"].astype(str)
            pr_content["ID"] = pr_content["ID"].astype(str)

            # Merge security flags with content
            review_data = security_data.merge(
                pr_content[["ID", "TITLE", "BODYSTRING"]], on="ID", how="left"
            )

            # Create file for security-flagged items
            security_only_data = review_data[review_data["SECURITY"] == 1].copy()
            security_review_path = os.path.join(output_path, "task6_review.csv")
            security_only_data.to_csv(security_review_path, index=False)
            print(f"Security candidates file created: {security_review_path}")

        else:
            print("WARNING: Could not load pull request content for review assistance")

    except Exception as error:
        print(f"Error creating review assistance files: {error}")


def load_pr_content_data(file_path):
    """
    Loads pull request content data, handling potential Git LFS pointer files.
    """

    if not os.path.exists(file_path):
        print(f"Pull request content file not found: {file_path}")
        return regen_data()

    try:
        content_data = pd.read_csv(file_path)

        # Check if this is actual data vs Git LFS pointer
        if len(content_data) > 500 and "TITLE" in content_data.columns:
            print(f"Successfully loaded {len(content_data)} pull request records")
            return content_data
        else:
            print("Detected Git LFS pointer file, attempting regen")
            return regen_data()

    except Exception as error:
        print(f"Error reading content file: {error}")
        return regen_data()


def regen_data():
    """
    Attempts to regenerate pull request data from the original Hugging Face dataset.
    """

    try:
        print("Retrieving pull request data from Hugging Face dataset...")

        raw_data = pd.read_parquet(
            "hf://datasets/hao-li/AIDev/all_pull_request.parquet"
        )

        # Transform to expected format
        regenerated_data = pd.DataFrame(
            {
                "TITLE": raw_data["title"],
                "ID": raw_data["id"],
                "AGENTNAME": raw_data["agent"],
                "BODYSTRING": raw_data["body"],
                "REPOID": raw_data["repo_id"],
                "REPOURL": raw_data["repo_url"],
            }
        )

        print("Successfully regenerated data")
        return regenerated_data

    except Exception as error:
        print(f"Data regeneration failed: {error}")
        return None


def main():
    print("Task 6: Manual Security Validation Setup")
    print("=" * 50)

    result = create_manual_security_validation()

    if result is not None:
        print("\nTask 6 setup completed")
    else:
        print("\nTask 6 setup failed")


if __name__ == "__main__":
    main()
