import os

import pandas as pd


def task2_process_repositories():
    """
    Task 2: Process all_repository data and create CSV with specific column mappings
    """

    try:
        print("Loading repository data from Hugging Face dataset...")

        df = pd.read_parquet("hf://datasets/hao-li/AIDev/all_repository.parquet")

        # Create the new dataframe with the column mappings
        task2_df = pd.DataFrame(
            {
                "REPOID": df["id"],
                "LANG": df["language"],
                "STARS": df["stars"],
                "REPOURL": df["url"],
            }
        )

        # Create output directory if it doesn't exist
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save to CSV file
        output_file = os.path.join(output_dir, "task2_repositories.csv")
        task2_df.to_csv(output_file, index=False)

        print(f"Task 2 completed successfully!")
        print(f"Output saved to: {output_file}")
        print(f"Number of records processed: {len(task2_df)}")

        return task2_df

    except Exception as e:
        print(f"Error processing Task 2: {str(e)}")
        return None


if __name__ == "__main__":
    print("Processing all_repository Data")
    print("=" * 50)

    result = task2_process_repositories()

    if result is not None:
        print("\nTask 2 execution completed")
    else:
        print("\nTask 2 execution failed")
