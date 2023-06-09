import argparse
import requests
import pandas as pd
import os
import urllib.parse

"""
usage: urlscan_util.py [-h] [--csv CSV] [--task_domains] [--page_domains] [--urls] [--malicious] [--api_key API_KEY] filename

Submits newline-delimited queries in TXT file to URLScan API. Checks for key in URLSCAN_API_KEY environment variable by default

positional arguments:
  filename              name of file containing urlscan queries

optional arguments:
  -h, --help            show this help message and exit
  --csv CSV, -c CSV     output csv path
  --task_domains, -t    print tasked domains
  --page_domains, -p    print page domains
  --urls, -u            print page urls
  --malicious, -m       return only malicious results
  --api_key API_KEY, -a API_KEY
                        URLScan API key (override environment variable check)
"""

def get_urlscan_api_key():
    URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY')
    return(URLSCAN_API_KEY)

def create_querylist(filename):
    querylist = []
    with open(str(filename), "r") as input:
        for line in input:
            line = line.strip()
            querylist.append(line)
    return(querylist)


def create_dataframe(querylist, api_key):
    df_list = []

    request_headers = {
        'api-key': api_key
    }

    for q in querylist:
        try:
            query = urllib.parse.quote(q, safe='')

            url = "https://www.urlscan.io/api/v1/search?q=" + query
            r = requests.get(url, headers=request_headers)
            data = r.json()

            results = data["results"]

            results_df = pd.json_normalize(results)

            df_list.append(results_df)

        except Exception as e: print(e)

    output = pd.concat(df_list)
    return(output)

def write_csv(df, csv_path):
    df.to_csv(str(csv_path))

def filter_malicious(df):
    malicious_df = df[df['verdicts.malicious'] == True]
    return(malicious_df)

def print_task_domains(df):
    print(*df['task.domain'].drop_duplicates().values,sep="\n")

def print_page_domains(df):
    print(*df['page.domain'].drop_duplicates().values,sep="\n")

def print_urls(df):
    print(*df['page.url'].drop_duplicates().values,sep="\n")

def main():
    parser = argparse.ArgumentParser(
            description="Submits newline-delimited queries in TXT file to URLScan API. Checks for key in URLSCAN_API_KEY environment variable by default"
        )
    parser.add_argument("filename", action="store", help="name of file containing urlscan queries")
    parser.add_argument("--csv", "-c", action="store",  help="output csv path")
    parser.add_argument("--task_domains", "-t", action="store_true", default=False, help="print tasked domains")
    parser.add_argument("--page_domains", "-p", action="store_true", default=False, help="print page domains")
    parser.add_argument("--urls", "-u", action="store_true", default=False, help="print page urls")
    parser.add_argument("--malicious", "-m", action="store_true", default=False, help="return only malicious results")
    parser.add_argument("--api_key", "-a", action="store", help="URLScan API key (override environment variable check)")
    args = parser.parse_args()
   
    if (args.api_key):
        api_key = args.api_key
    else:
        api_key = get_urlscan_api_key()
    
    filename = args.filename
    
    querylist = create_querylist(filename)

    df = create_dataframe(querylist, api_key)

    if(args.malicious):
        df = filter_malicious(df)
    
    if(args.csv):
        write_csv(df, args.csv)
    
    if(args.task_domains):
        print_task_domains(df)
    
    if(args.page_domains):
        print_page_domains(df)
    
    if(args.urls):
        print_urls(df)

if __name__ == '__main__':
    main()