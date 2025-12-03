import os

import pandas as pd


def task3_process_pr_task_types():
    """
    Task 3: Process pr_task_type data and create CSV with specific column mappings
    """

    try:
        print("Loading PR task type data from Hugging Face dataset...")

        df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_task_type.parquet")

        # Create the new dataframe with the column mappings
        task3_df = pd.DataFrame(
            {
                "PRID": df["id"],
                "PRTITLE": df["title"],
                "PRREASON": df["reason"],
                "PRTYPE": df["type"],
                "CONFIDENCE": df["confidence"],
            }
        )

        # Create output directory if it doesn't exist
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save to CSV file
        output_file = os.path.join(output_dir, "task3_pr_task_types.csv")
        task3_df.to_csv(output_file, index=False)

        print("Task 3 completed successfully")
        print(f"Output saved to: {output_file}")
        print(f"Number of records processed: {len(task3_df)}")

        return task3_df

    except Exception as e:
        print(f"Error processing Task 3: {str(e)}")
        return None


if __name__ == "__main__":
    print("Processing PR Task Type Data")
    print("=" * 50)

    result = task3_process_pr_task_types()

    if result is not None:
        print("\nTask 3 execution completed")
    else:
        print("\nTask 3 execution failed")
