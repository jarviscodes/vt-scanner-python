import os
import sys
import win32file
import win32con

import time

import click
import requests
import itertools
from sensitive import APIKEY
from win10toast import ToastNotifier


params = {'apikey': APIKEY}

is_watcher = False

ACTION = {
	1: "Created",
	2: "Deleted",
	3: "Updated",
	4: "Renamed from",
	5: "Renamed to"
}

FILE_LIST_DIRECTORY = 0x0001

def _print_prefix(character, color):
	click.secho('[', nl=False)
	click.secho(character, fg=color, nl=False)
	click.secho('] ', nl=False)

def _print_prefixed_message(character, color, message):
	_print_prefix(character, color)
	click.secho(message)

def run_as_watcher(directory):
	path_to_watch = directory

	hDir = win32file.CreateFile(
		path_to_watch,
		FILE_LIST_DIRECTORY,
		win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
		None,
		win32con.OPEN_EXISTING,
		win32con.FILE_FLAG_BACKUP_SEMANTICS,
		None
	)
	try:
		while 1:
				results = win32file.ReadDirectoryChangesW (
					hDir,
					1024,
					True,
					win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
					win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
					win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
					win32con.FILE_NOTIFY_CHANGE_SIZE |
					win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
					win32con.FILE_NOTIFY_CHANGE_SECURITY,
					None,
					None
				)
				for action, file in results:
					full_filename = os.path.join(path_to_watch, file)
					if ACTION.get(action, "Unknown") == "Created":
						time.sleep(1)
						scan_single_file(full_filename)
						
	except KeyboardInterrupt:
		print("Exiting!")
		exit()

def scan_single_file(file):
	url = 'https://www.virustotal.com/vtapi/v2/file/scan'
	with open(file, "rb") as _f:
		with requests.Session() as _sess:
			response = _sess.post(url, files={'file': _f}, params=params)
	json_resp = response.json()
	resource = json_resp['resource']
	_print_prefixed_message('*', 'yellow', f'Getting Scan Result for {file}')
	generate_scan_report(resource)
	
	
def print_vendor_table(vendordict):
	for vd in vendordict.keys():
		if vendordict[vd]['detected']:
			_print_prefix('!!', 'red')
			click.secho(vd, fg='red')
		else:
			_print_prefix(':)', 'green')
			click.secho(vd, fg='green')
	
	
def print_positives(positives, total):
	if positives > 0:
		hcolor = 'red'
		symbol = '!!'
	else:
		hcolor = 'green'
		symbol = ':)'
		
	_print_prefix(symbol, hcolor)
	click.secho('Positives: ', nl=False)
	click.secho(f"{positives}", fg=hcolor, nl=False)
	click.secho(" / ", nl=False)
	click.secho(f"{total}", fg='green')
	
	
def print_scan_report(vendordict, permalink, scan_date, verbose_msg, total, positives):
	_print_prefixed_message('+', 'green', 'Scan Completed')
	print_positives(positives, total)
	if not is_watcher:
		click.secho('Show Detail? [y/n]: ', nl=False)
		c = click.getchar()
		click.echo()
		if c.upper() == 'Y':
			print_vendor_table(vendordict)
		if c.upper() == 'N':
			click.secho("Exiting!")
		exit()
	else:
		# Show results in Toast!
		toaster = ToastNotifier()
		toaster.show_toast("Scan Complete!", f"Positives: {positives} / {total}", duration=5, icon_path=".\\favicon.ico")		

def generate_scan_report(resource_id):
	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	local_params = {'resource': resource_id}
	
	full_params = dict()
	full_params.update(params)
	full_params.update(local_params)
	
	with requests.Session() as _sess:
		response = _sess.get(url, params=full_params)
	
	json_resp = response.json()
	for key in json_resp.keys():
		if key == "scans":
			vendor_table = json_resp[key]
		elif key == "verbose_msg":
			result_message = json_resp[key]
		elif key == "total":
			total_scans = json_resp[key]
		elif key == "positives":
			total_positives = json_resp[key]
		elif key == "permalink":
			permalink = json_resp[key]
		elif key == "scan_date":
			scan_date = json_resp[key]
	
	print_scan_report(vendor_table, permalink, scan_date, result_message, total_scans, total_positives)	

def parse_cli_options(**kwargs):
	global is_watcher
	
	watcher_opt = kwargs['watcher']
	dir_opt = kwargs['directory']
	file_opt = kwargs['file']
	
	if watcher_opt:
		_print_prefixed_message("*", "cyan", "Running as watcher!")
		is_watcher = True
		
		if dir_opt is None:
			_print_prefixed_message("E", "red", "You need to specify a directory to watch when running as Watcher!")
			_print_prefixed_message("i", "cyan", "Run VTScan.py --help for more info")
			exit()
			
	elif file_opt is None:
		_print_prefixed_message("E", "red", "You must specify a file when running interactively")
		_print_prefixed_message("i", "cyan", "Run VTScan.py --help for more info")
		exit()
	
	return watcher_opt, dir_opt, file_opt
	
@click.command()
@click.option("-w", "--watcher", default=False, is_flag=True)
@click.option("-D", "--directory", type=str, default=None)
@click.option("-f", "--file", type=str, default=None)
def main(**kwargs):
	watcher_opt, dir_opt, file_opt = parse_cli_options(**kwargs)
	if watcher_opt:
		run_as_watcher(dir_opt)
	else:
		scan_single_file(file_opt)


if __name__ == '__main__':
	main()