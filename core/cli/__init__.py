import argparse
import multiprocessing
import os
from typing import List, Type

from cmd2 import Cmd, Cmd2ArgumentParser, with_argparser
from prettytable import PrettyTable
from sqlalchemy.orm import Session

from core.analysis import Analyzed
from core.analysis.callbacks import analyzed_callback
from core.db import ENGINE, ImplicitIntent, ExportedComponent, Service
from core.logging import detect, info
from core.process import ProcessManager
from core.utils import collect_apks


class SnakeBite(Cmd):
    def __init__(self):
        super().__init__()
        self.prompt = "(snakebite) > "
        self.debug = True

    SCAN_PARSER = Cmd2ArgumentParser()
    SCAN_PARSER.add_argument("-p", "--path", completer=Cmd.path_complete)
    SCAN_PARSER.add_argument("-b", "--batch", action="store_true")

    @with_argparser(SCAN_PARSER)
    def do_scan(self, args: argparse.Namespace) -> None:
        if args.batch:
            if os.path.isdir(args.path):
                in_queue = multiprocessing.Queue()
                apks = collect_apks(args.path)
                for i in apks:
                    in_queue.put(i)
                # TODO ~ Add command line parameter for number of processes
                process_manager = ProcessManager.create(10, in_queue, Analyzed.analyze, analyzed_callback)
                process_manager.run()
        else:
            if os.path.isfile(args.path):
                in_queue = multiprocessing.Queue()
                in_queue.put(args.path)
                process_manager = ProcessManager.create(1, in_queue, Analyzed.analyze, analyzed_callback)
                process_manager.run()

    RECEIVER_PARSER = Cmd2ArgumentParser()
    RECEIVER_PARSER.add_argument("--intent-filters", action="store_true")

    @with_argparser(RECEIVER_PARSER)
    def do_exported_receivers(self, args: argparse.Namespace) -> None:
        table = PrettyTable(["component_type", "component_name"])
        table.align = "l"
        with Session(ENGINE) as session:
            results = session.query(ExportedComponent).filter_by(component_type="receiver").all()
            for i in results:
                table.add_row([i.component_type, i.component_name])
        print(table)

    SERVICE_PARSER = Cmd2ArgumentParser()
    SERVICE_PARSER.add_argument("--intent-filters", action="store_true")
    SERVICE_PARSER.add_argument("--rpc-methods", action="store_true")

    @with_argparser(SERVICE_PARSER)
    def do_exported_services(self, args: argparse.Namespace) -> None:
        if args.rpc_methods:
            with Session(ENGINE) as session:
                results: List[Type[Service]] = session.query(Service).all()
                for i in results:
                    detect(i.component_name)
                    for k, v in i.rpc_methods.items():
                        if isinstance(v, list):
                            for rpc_method in v:
                                info(f"\t=> {rpc_method}")
        elif args.intent_filters:
            with Session(ENGINE) as session:
                results: List[Type[Service]] = session.query(Service).all()
                for i in results:
                    detect(i.component_name)
                    if len(i.intent_data["actions"]) > 0:
                        for action in i.intent_data["actions"]:
                            info(f"\t action => {action}")

        else:
            table = PrettyTable(["component_type", "component_name"])
            table.align = "l"
            with Session(ENGINE) as session:
                results = session.query(ExportedComponent).filter_by(component_type="service").all()
                for i in results:
                    table.add_row([i.component_type, i.component_name])
            print(table)

    IMPLICIT_INTENT_PARSER = Cmd2ArgumentParser()
    IMPLICIT_INTENT_PARSER.add_argument("--source-method", type=str)
    IMPLICIT_INTENT_PARSER.add_argument("--instructions", action="store_true")

    @with_argparser(IMPLICIT_INTENT_PARSER)
    def do_implicit_intents(self, args: argparse.Namespace) -> None:
        table = PrettyTable(["intent_method", "class_name", "source_method"])
        table.align = "l"
        with Session(ENGINE) as session:
            records: List[Type[ImplicitIntent]] = session.query(ImplicitIntent).all()
            for i in records:
                table.add_row([i.intent_method, i.class_name, i.source_method])
        print(table)

    def do_apk_backups(self, _):
        pass
