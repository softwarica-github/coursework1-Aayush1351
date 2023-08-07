from invoke import Responder
import requests
import argparse
import concurrent.futures
import os
import re
import sys

def get_valid_file_path(prompt):
    while True:
        file_path = input(prompt)
        if not os.path.isfile(file_path):
            print("Invalid file path. Please try again.")
        else:
            return file_path

def url_found(payload):
    url = f"{target_url}/{payload}"
    # print(url)
    try:
        response = requests.get(url, allow_redirects=True)
        # print(response)
        if response.status_code != 404 and response.status_code != 403:
            print(f"[+] Found: {response.url} (Status Code: {response.status_code})")
            all_results.append(response.url)
            for redirect in response.history:
                print(f"  - Redirection from: {redirect.url} (Status Code: {redirect.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error occurred for {url}: {e}")
    return None

def subDomain_fuzz(sub_domain):
    sub_url = f"https://www.{sub_domain}.{input_url}"
    try:
        response = requests.get(sub_url, allow_redirects=True)
        if response.status_code != 404 and response.status_code != 403:
            print(f"[+] Found: {sub_url} (Status Code: {response.status_code})")
            all_results.append(sub_url)
            for redirect in response.history:
                print(f"  - Redirection from: {redirect.url} (Status Code: {redirect.status_code})")
    except requests.exceptions.RequestException as errors:
        pass

def ext_file_fuzz(filename,extension):
    # ext = input("Enter the extension name: ")
    ext_url = f"{target_url}/{filename}.{extension}"
    try:
        response = requests.get(ext_url, allow_redirects=True)
        if response.status_code != 404 and response.status_code != 403:
            print(f"[+] Found: {ext_url} (Status Code: {response.status_code})")
            all_results.append(ext_url)
            for redirect in response.history:
                print(f"  - Redirection from: {redirect.url} (Status Code: {redirect.status_code})")
    except requests.exceptions.RequestException as ext_error:
        print(f"[-] Error occurred for {ext_url}: {ext_error}")

def file_fuzz(using_words):
    hidden_file_url = f"{target_url}/.{using_words}"
    try:
        response = requests.get(hidden_file_url, allow_redirects=True)
        if response.status_code != 404 and response.status_code != 403:
            print(f"[+] Found: {hidden_file_url} (Status Code: {response.status_code})")
            all_results.append(hidden_file_url)  # Append to all_results
            for redirect in response.history:
                print(f"  - Redirection from: {redirect.url} (Status Code: {redirect.status_code})")
    except requests.exceptions.RequestException as file_fuzz_error:
        print(f"[-] Error occurred for {hidden_file_url}: {file_fuzz_error}")

# Breadth-First Search (BFS)
def bfs_url_search(payload):
    queue = [target_url]
    bfs_results = []
    while queue:
        current_url = queue.pop(0)
        url = f"{current_url}/{payload}"
        try:
            response = requests.get(url, allow_redirects=True)
            if response.status_code != 404 and response.status_code != 403:
                print(f"[+] Found: {url} (Status Code: {response.status_code})")
                bfs_results.append(url)
                for redirect in response.history:
                    print(f"  - Redirection from: {redirect.url} (Status Code: {redirect.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error occurred for {url}: {e}")
        # Add subdirectories or endpoints to the queue for further exploration
        if response.status_code == 200 and response.headers.get('content-type') == 'text/html':
            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            for link in links:
                if not link.startswith('http'):
                    queue.append(f"{current_url}/{link}")
    return bfs_results

# Depth-First Search (DFS)
def dfs_url_search(payload):
    stack = [target_url]
    dfs_results = []
    while stack:
        current_url = stack.pop()
        url = f"{current_url}/{payload}"
        try:
            response = requests.get(url)
            if response.status_code != 404 and response.status_code != 403:
                print(f"[+] Found: {url} (Status Code: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error occurred for {url}: {e}")
        # Add subdirectories or endpoints to the stack for further exploration
        if response.status_code == 200 and response.headers.get('content-type') == 'text/html':
            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            for link in links:
                if not link.startswith('http'):
                    stack.append(f"{current_url}/{link}")
    return dfs_results

# Regex Matching
def regex_match(response, pattern):
    matches = re.findall(pattern, response.text)
    regex_results = []
    for match in matches:
        print(f"[+] Match found: {match}")
        regex_results.append(match)
    return regex_results

# Crawling or Web Scraping
def crawl_urls():
    visited_urls = set()
    queue = [target_url]
    crawl_results = []

    while queue:
        current_url = queue.pop(0)
        try:
            response = requests.get(current_url)
            if response.status_code == 200 and response.headers.get('content-type') == 'text/html':
                visited_urls.add(current_url)
                crawl_results.append(current_url)
                links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
                for link in links:
                    if not link.startswith('http'):
                        new_url = f"{current_url}/{link}"
                        if new_url not in visited_urls:
                            queue.append(new_url)
        except requests.exceptions.RequestException as e:
            print(f"[-] Error occurred for {current_url}: {e}")
    return crawl_results

# Bubble Sort algorithm
def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]

# Define the command-line arguments
parser = argparse.ArgumentParser(description="Advanced Fuzzing Tool")
parser.add_argument("url", help="URL to be fuzzed")
parser.add_argument("--wordlist", help="Path to the wordlist file")
parser.add_argument("--subdomains", help="Path to the subdomain file")
parser.add_argument("--files", help="Path to the wordlistssssss file")
parser.add_argument("--filelist", help="Path to the file list for file fuzzing")
args = parser.parse_args()

# Set the target URL
input_url = args.url
target_url = f"https://{input_url}"
response = requests.get(target_url)

# Load wordlist
if args.wordlist:
    wordlist_path = args.wordlist
    with open(wordlist_path, "r") as wordlist_file:
        word_list = wordlist_file.read().splitlines()
else:
    print("No wordlist specified.")
    sys.exit()

# Load subdomains
if args.subdomains:
    subdomains_path = args.subdomains
    with open(subdomains_path, "r") as subdomains_file:
        subdomains = subdomains_file.read().splitlines()
else:
    print("No subdomain file specified.")
    sys.exit()

# Load files for extension
if args.files:
    file_path = args.files
    with open(file_path, "r") as file_path_list:
        filenames = file_path_list.read().splitlines()
else:
    print("No extensions file specified.")
    sys.exit()

# Load file list
if args.filelist:
    file_list_path = args.filelist
    with open(file_list_path, "r") as file_list_file:
        file_list = file_list_file.read().splitlines()
else:
    print("No file list specified.")
    sys.exit()

# Perform fuzzing
print("Performing Fuzzing...\n")

all_results = []

# URL Fuzzing
print("URL Fuzzing:")
with concurrent.futures.ThreadPoolExecutor() as executor:
    url_fuzz_results = list(executor.map(url_found, word_list))
    url_fuzz_results = [result for result in url_fuzz_results if result is not None]
    all_results.extend(url_fuzz_results)

# Subdomain Fuzzing
print("\nSubdomain Fuzzing:")
with concurrent.futures.ThreadPoolExecutor() as exec:
    subdomain_fuzz_results = list(exec.map(subDomain_fuzz, subdomains))
    subdomain_fuzz_results = [result for result in subdomain_fuzz_results if result is not None]
    all_results.extend(subdomain_fuzz_results)

# Extension Fuzzing
print("\nExtension Fuzzing:")
extension = input("Enter the extension name: ")
with concurrent.futures.ThreadPoolExecutor() as execute:
    ext_fuzz_results = list(execute.map(ext_file_fuzz, filenames, [extension] * len(filenames)))
    ext_fuzz_results = [result for result in ext_fuzz_results if result is not None]
    all_results.extend(ext_fuzz_results)

# File Fuzzing
print("\nFile Fuzzing:")
with concurrent.futures.ThreadPoolExecutor() as ex:
    file_fuzz_results = list(ex.map(file_fuzz, file_list))
    file_fuzz_results = [result for result in file_fuzz_results if result is not None]
    all_results.extend(file_fuzz_results)

# URL Searching
print("\nURL Searching:")
bfs_results = bfs_url_search("admin")
dfs_results = dfs_url_search("admin")
all_results.extend(bfs_results)
all_results.extend(dfs_results)

# Regex Matching
print("\nRegex Matching:")
regex_pattern = r'<a href=[\'"]?([^\'" >]+)'
regex_results = regex_match(response, regex_pattern)
all_results.extend(regex_results)

# Crawling
print("\nCrawling:")
crawl_results = crawl_urls()
all_results.extend(crawl_results)

# Sort the results
bubble_sort(all_results)

# Print the results
print("\n[+] All Results:")
for result in all_results:
    print(result)

# Write all the results to a single file
output_file_path = "all_results.txt"
with open(output_file_path, "w") as output_file:
    for result in all_results:
        output_file.write(result + "\n")
print(f"\nAll results saved to {output_file_path}")
