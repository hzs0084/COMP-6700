import pandas as pd
import yaml

# 1) read the spreadsheet
def read_access_matrix(xlsx_path):
    """
    Reads data.xlsx and returns a DataFrame.
    Assumptions:
    - First column is the user id (like u0, u1, etc.)
    - The next columns are file names with permissions like "777", "444", etc.
    - Empty cells mean NO permissions.
    """
    try:
        df = pd.read_excel(xlsx_path, dtype=str)
    except Exception as e:
        print("Could not read Excel file:", e)
        return None

    # set the first column as user index
    user_col = df.columns[0]
    df = df.set_index(user_col)

    # make sure strings are clean; keep empty as NaN
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)

    return df

# 2) tiny helpers for checks
def is_777(val):
    return isinstance(val, str) and val == "777"

def is_444(val):
    return isinstance(val, str) and val == "444"

def has_read(val):
    """
    "read" bit is set if any octal digit is 4, 5, 6, or 7.
    We just check each character that is a digit.
    """
    if not isinstance(val, str):
        return False
    for ch in val:
        if ch in ["4", "5", "6", "7"]:
            return True
    return False

def is_empty(val):
    return (val is None) or (not isinstance(val, str)) or (val.strip() == "")

# 3) the 6 separate functions
def count_users_all_777(df):
    count = 0
    for user, row in df.iterrows():
        all_777 = True
        for col in df.columns:
            if not is_777(row[col]):
                all_777 = False
                break
        if all_777:
            count += 1
    return count

def count_users_any_777(df):
    count = 0
    for user, row in df.iterrows():
        any_777 = False
        for col in df.columns:
            if is_777(row[col]):
                any_777 = True
                break
        if any_777:
            count += 1
    return count

def count_users_all_444(df):
    count = 0
    for user, row in df.iterrows():
        all_444 = True
        for col in df.columns:
            if not is_444(row[col]):
                all_444 = False
                break
        if all_444:
            count += 1
    return count

def count_users_any_444(df):
    count = 0
    for user, row in df.iterrows():
        any_444 = False
        for col in df.columns:
            if is_444(row[col]):
                any_444 = True
                break
        if any_444:
            count += 1
    return count

def count_users_any_read(df):
    count = 0
    for user, row in df.iterrows():
        any_r = False
        for col in df.columns:
            if has_read(row[col]):
                any_r = True
                break
        if any_r:
            count += 1
    return count

def count_users_all_none(df):
    count = 0
    for user, row in df.iterrows():
        all_none = True
        for col in df.columns:
            if not is_empty(row[col]):
                all_none = False
                break
        if all_none:
            count += 1
    return count

# 4) build the hashmap (dict)
def build_permission_hashmap(df):
    """
    Makes { user: {file: permission, ...} } but
    only for users who have permissions on at least 2 files.
    """
    result = {}
    for user, row in df.iterrows():
        user_map = {}
        for col in df.columns:
            val = row[col]
            if isinstance(val, str) and val.strip() != "":
                user_map[col] = val
        if len(user_map) >= 2:
            result[str(user)] = user_map
    return result

# 5) write YAML file
def export_yaml(data, out_path):
    try:
        with open(out_path, "w") as f:
            yaml.safe_dump(data, f, sort_keys=True)
    except Exception as e:
        print("Could not write YAML:", e)

# 6) main
def main():
    xlsx_path = "data.xlsx"
    df = read_access_matrix(xlsx_path)
    if df is None:
        return

    # print a tiny preview so we can see we loaded it
    print("\nPreview (first 10 users):")
    try:
        print(df.head(10))
    except Exception:
        pass

    # compute all answers
    ans_2_i   = count_users_all_777(df)
    ans_2_ii  = count_users_any_777(df)
    ans_2_iii = count_users_all_444(df)
    ans_2_iv  = count_users_any_444(df)
    ans_2_v   = count_users_any_read(df)
    ans_2_vi  = count_users_all_none(df)

    print("\nAnswers:")
    print("2.i   (777 for all files):", ans_2_i)
    print("2.ii  (777 for at least one file):", ans_2_ii)
    print("2.iii (444 for all files):", ans_2_iii)
    print("2.iv  (444 for at least one file):", ans_2_iv)
    print("2.v   (read permission for at least one file):", ans_2_v)
    print("2.vi  (NO permission for all files):", ans_2_vi)

    # build hashmap and export
    hmap = build_permission_hashmap(df)
    # print(f"\n{hmap}")
    print("\nUsers with >= 2 files:", len(hmap))
    export_yaml(hmap, "access_map.yaml")
    print("YAML written to access_map.yaml")

if __name__ == "__main__":
    main()
