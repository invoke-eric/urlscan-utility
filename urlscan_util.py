import argparse
import requests
import pandas as pd
import os
import urllib.parse

"""
usage: urlscan_util.py [-h] [--csv CSV] [--task_domains] [--page_domains] [--urls] [--malicious] [--api_key API_KEY] [--size SIZE]
                       [--filter_filename FILTER_FILENAME] [--results_csv RESULTS_CSV] [--download]
                       filename

Submits newline-delimited queries in TXT file to URLScan API. Checks for key in URLSCAN_API_KEY environment variable by default

positional arguments:
  filename              name of file containing urlscan queries

options:
  -h, --help            show this help message and exit
  --csv CSV, -c CSV     output search results csv path
  --task_domains, -t    print tasked domains
  --page_domains, -p    print page domains
  --urls, -u            print page urls
  --malicious, -m       return only malicious results
  --api_key API_KEY, -a API_KEY
                        URLScan API key (override environment variable check)
  --size SIZE, -s SIZE  Number of results returned, max 10 000, default 100
  --filter_filename FILTER_FILENAME, -f FILTER_FILENAME
                        name of filename to filter results for
  --results_csv RESULTS_CSV, -r RESULTS_CSV
                        output filtered results csv path
  --download, -d        download filtered files, only applies if -f flag used
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


def create_dataframe(querylist, api_key, size) -> pd.DataFrame:
    df_list = []

    request_headers = {
        'api-key': api_key
    }

    for q in querylist:
        try:
            query = urllib.parse.quote(q, safe='')
            

            url = "https://www.urlscan.io/api/v1/search?q=" + query + "&size=" + str(size)
            
            r = requests.get(url, headers=request_headers)
            data = r.json()

            results = data["results"]

            results_df = pd.json_normalize(results)

            df_list.append(results_df)

        except Exception as e: print(e)

    output = pd.concat(df_list)
    return(output)

def filter_filename(input_df:pd.DataFrame, filename:str, api_key:str) -> pd.DataFrame:
    request_headers = {
        'api-key': api_key}
    
    dfs = []
    for u in input_df['_id']:
        try:
            query = urllib.parse.quote(u, safe='')
            url = "https://www.urlscan.io/api/v1/result/" + query
            r = requests.get(url, headers=request_headers)
            data = r.json()
            df = pd.json_normalize(data['data']['requests'])
            dfs.append(df)
        except Exception as e: print(e)

    c = pd.concat(dfs)

    matching_filename = c[c['request.request.url'].astype('str').str.contains(filename) & c['response.size'] > 0]

    domains_of_interest = matching_filename['request.documentURL'].apply(lambda x: urllib.parse.urlparse(x)[1]).unique()

    filtered_results = c[c['request.documentURL'].str.contains('|'.join(domains_of_interest), case=False, na=False)]

    return filtered_results, matching_filename

def get_files(matching_filename: pd.DataFrame, api_key:str):
    request_headers = {
        'api-key': api_key}

    nonzero = matching_filename[['request.request.url', 'response.size', 'response.hash']].dropna()

    for h in nonzero['response.hash'].unique():
        try:
            query = urllib.parse.quote(h, safe='')
            url = "https://urlscan.io/responses/" + query
            r = requests.get(url, headers=request_headers)
            content = r.content
            with open(h, "wb") as file: #have to use the b flag because the content is of type 'bytes'
                file.write(content)
                print(f"downloaded {h}")
            
        except Exception as e: print(e)


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
    parser.add_argument("--csv", "-c", action="store",  help="output search results csv path")
    parser.add_argument("--task_domains", "-t", action="store_true", default=False, help="print tasked domains")
    parser.add_argument("--page_domains", "-p", action="store_true", default=False, help="print page domains")
    parser.add_argument("--urls", "-u", action="store_true", default=False, help="print page urls")
    parser.add_argument("--malicious", "-m", action="store_true", default=False, help="return only malicious results")
    parser.add_argument("--api_key", "-a", action="store", help="URLScan API key (override environment variable check)")
    parser.add_argument("--size", "-s", action="store", help="Number of results returned, max 10 000, default 100", default="100")
    parser.add_argument("--filter_filename", "-f", action="store", help ="name of filename to filter results for")
    parser.add_argument("--results_csv", "-r", action="store", help = "output filtered results csv path")
    parser.add_argument("--download", "-d", action ="store_true", default=False, help ="download filtered files, only applies if -f flag used")
    args = parser.parse_args()
   
    if (args.api_key):
        api_key = args.api_key
    else:
        api_key = get_urlscan_api_key()
        
    size = args.size

    queryfile = args.filename
    
    querylist = create_querylist(queryfile)

    df = create_dataframe(querylist, api_key, size)

    if(args.malicious):
        df = filter_malicious(df)
    
    if(args.filter_filename):
        filename = args.filter_filename
        filtered_df, matching_filename = filter_filename(df, filename, api_key)

        if(args.results_csv):
            write_csv(filtered_df, args.results_csv)
        
        if(args.download):
            get_files(matching_filename, api_key)

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