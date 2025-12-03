import os

import pandas as pd


def task1_process_pull_requests():
    """
    Task 1: Process all_pull_request data and create CSV with specific column mappings
    """
    try:
        print("Loading pull request data from Hugging Face dataset...")

        try:
            df = pd.read_parquet("hf://datasets/hao-li/AIDev/all_pull_request.parquet")
        except Exception as auth_error:
            if "401" in str(auth_error) or "authentication" in str(auth_error).lower():
                print("Authentication required")

        print(f"Loaded {len(df)} pull request records")
        print(f"Available columns: {list(df.columns)}")

        # Create the new dataframe with the columns
        task1_df = pd.DataFrame(
            {
                "TITLE": df["title"],
                "ID": df["id"],
                "AGENTNAME": df["agent"],
                "BODYSTRING": df["body"],
                "REPOID": df["repo_id"],
                "REPOURL": df["repo_url"],
            }
        )

        # Create output directory if it doesn't exist
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save to CSV file
        output_file = os.path.join(output_dir, "task1_pull_requests.csv")
        task1_df.to_csv(output_file, index=False)

        print(f"Task 1 completed successfully!")
        print(f"Output saved to: {output_file}")
        print(f"Number of records processed: {len(task1_df)}")

        return task1_df

    except Exception as e:
        print(f"Error processing Task 1: {str(e)}")
        return None


if __name__ == "__main__":
    print("Processing Pull Request Data")
    print("=" * 50)

    result = task1_process_pull_requests()

    if result is not None:
        print("\nTask 1 completed")
    else:
        print("\nTask 1 failed")
