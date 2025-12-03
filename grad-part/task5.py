import os
import re

import pandas as pd


def build_security_pattern():
    """
    Build a regex pattern for the security-related keywords specified in the project.
    Matching is case-insensitive and done on raw substrings.
    """

    # Keywords from the project description (Task-5)
    keywords = [
        "race",
        "racy",
        "buffer",
        "overflow",
        "stack",
        "integer",
        "signedness",
        "underflow",
        "improper",
        "unauthenticated",
        "gain access",
        "permission",
        "cross site",
        "css",
        "xss",
        "denial service",
        "dos",
        "crash",
        "deadlock",
        "injection",
        "request forgery",
        "csrf",
        "xsrf",
        "forged",
        "security",
        "vulnerability",
        "vulnerable",
        "exploit",
        "attack",
        "bypass",
        "backdoor",
        "threat",
        "expose",
        "breach",
        "violate",
        "fatal",
        "blacklist",
        "overrun",
        "insecure",
    ]

    escaped_keywords = [re.escape(k) for k in keywords]
    pattern_str = "(" + "|".join(escaped_keywords) + ")"
    return re.compile(pattern_str, flags=re.IGNORECASE)


def task5_process_security_flags():
    """
    Task 5:
    From the outputs of Task-1 and Task-3, create a CSV with:

    ID: ID of the pull request
    AGENT: The name of the agent
    TYPE: The type of the pull request
    CONFIDENCE: Confidence for the type
    SECURITY: 1 if any security keyword appears in title or body, 0 otherwise
    """

    try:
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Take the input from other CSVs like Tasks 1 and 3
        task1_file = os.path.join(output_dir, "task1_pull_requests.csv")
        task3_file = os.path.join(output_dir, "task3_pr_task_types.csv")

        print(f"Loading Task-1 CSV from: {task1_file}")
        print(f"Loading Task-3 CSV from: {task3_file}")

        task1_df = pd.read_csv(task1_file)
        task3_df = pd.read_csv(task3_file)

        # Sanity info
        print(f"Task-1 records: {len(task1_df)}")
        print(f"Task-3 records: {len(task3_df)}")

        # Make sure IDs are comparable and are cast to both as a string
        task1_df["ID"] = task1_df["ID"].astype(str)
        task3_df["PRID"] = task3_df["PRID"].astype(str)

        # Merge on PR ID
        print("Merging Task-1 and Task-3 data on ID/PRID...")
        merged = task1_df.merge(
            task3_df[["PRID", "PRTYPE", "CONFIDENCE"]],
            left_on="ID",
            right_on="PRID",
            how="inner",
        )

        print(f"Number of merged records: {len(merged)}")

        # No longer need the PRID 
        merged = merged.drop(columns=["PRID"])

        # Prepare text to scan: TITLE + BODYSTRING
        merged["TITLE"] = merged["TITLE"].fillna("")
        merged["BODYSTRING"] = merged["BODYSTRING"].fillna("")
        combined_text = merged["TITLE"] + " " + merged["BODYSTRING"]

        # Build keyword pattern and compute SECURITY flag
        security_pattern = build_security_pattern()
        print("Computing SECURITY flag based on keyword scan of title + body...")

        merged["SECURITY"] = combined_text.str.contains(
            security_pattern,
            na=False,
        ).astype(int)

        # Build final Task-5 dataframe with required columns
        task5_df = merged[
            ["ID", "AGENTNAME", "PRTYPE", "CONFIDENCE", "SECURITY"]
        ].rename(
            columns={
                "AGENTNAME": "AGENT",
                "PRTYPE": "TYPE",
            }
        )

        # Output
        output_file = os.path.join(output_dir, "task5_pr_security_summary.csv")
        task5_df.to_csv(output_file, index=False)
        print(f"Task-5 output saved to: {output_file}")
        print(f"Number of records in Task-5 CSV: {len(task5_df)}")

        return task5_df

    except Exception as e:
        print(f"Error processing Task 5: {str(e)}")
        return None


if __name__ == "__main__":
    print("Processing PR Security Flags (Task 5)")
    print("=" * 50)

    result = task5_process_security_flags()

    if result is not None:
        print("\nTask 5 execution completed")
    else:
        print("\nTask 5 execution failed")
