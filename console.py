#!/usr/bin/python3
'''console module'''

import cmd
from models import storage
import models
from models.base_model import BaseModel
# import all models here
from models.user import User
from models.todo import Todo


class Console(cmd.Cmd):
    '''Command line program for testing the system'''

    prompt = "(console) "
    intro = "Welcome to the console v0.0.1.\nType help or ? to list commands.\n"

    def do_quit(self, args):
        """Quits the console"""
        print('Bye bye')
        return True

    def do_EOF(self, args):
        """Quits the console"""
        print('Bye bye')
        return True

    def do_create(self, args):
        """Creates a new instance of a Model, saves it (to the JSON file) and prints the id. Ex: $ create BaseModel"""

        if args == '':
            print("** class name missing **")

            return

        line = self.parseline(args)
        classname = line[0]

        if classname not in globals().keys():
            print("** class doesn't exist **")
            return

        params = line[1].split(' ')
        obj = globals()[classname]()
        if line[1]:
            for param in params:
                print(param)
                k, v = param.split('=')
                val = ''
                if v.startswith('"'):
                    for c in v:
                        if c != '"':
                            val += c
                    val_arr = val.split('_')
                    val = ' '.join(val_arr)
                    setattr(obj, k, val)
                elif '.' in v:
                    setattr(obj, k, float(v))
                elif v == 'True':
                    setattr(obj, k, bool(v))
                elif v == 'False':
                    setattr(obj, k, bool(v))
                else:
                    setattr(obj, k, int(v))
        obj.save()
        print(obj.id)

    def do_show(self, args):
        """Prints the string representation of an instance based on the class name and id. Ex: $ show BaseModel 1234-1234-1234."""

        if args == '':
            print("** class name missing **")
            return

        args_list = args.split(" ")

        if args_list[0] not in globals().keys():
            print("** class doesn't exist **")
            return

        if len(args_list) != 2:
            print("** instance id missing **")
            return

        k = f"{args_list[0]}.{args_list[1]}"
        objs = storage.all()

        if k not in objs.keys():
            print("** no instance found **")
            return
        print(objs[k])

    def do_destroy(self, args):
        """Deletes an instance based on the class name and id"""

        if args == '':
            print("** class name missing **")
            return

        args_list = args.split(" ")

        if args_list[0] not in globals().keys():
            print("** class doesn't exist **")
            return

        if len(args_list) != 2:
            print("** instance id missing **")
            return

        k = f"{args_list[0]}.{args_list[1]}"
        objs = storage.all()

        if k not in objs.keys():
            print("** no instance found **")
            return

        del objs[k]
        storage.save()

    def do_clear(self, args):
        '''Clears the screen'''
        import os
        os.system('clear')
        return

    def do_all(self, args):
        """Prints all string representation of all instances based or not on the class name."""

        all_objs = []
        objs = storage.all()
        if args == '':
            for v in objs.values():
                all_objs.append(str(v))
            print(all_objs)
            return

        args_list = args.split(" ")

        if args_list[0] not in globals().keys():
            print("** class doesn't exist **")
            return

        for v in objs.values():
            if v.__class__.__name__ == args_list[0]:
                all_objs.append(str(v))
        print(all_objs)
        return

    def do_count(self, args):
        """Prints count of all instances based or not on the class name."""

        all_objs = []
        objs = storage.all()
        if args == '':
            for v in objs.values():
                all_objs.append(str(v))
            print(len(all_objs))
            return

        args_list = args.split(" ")

        if args_list[0] not in globals().keys():
            print("** class doesn't exist **")
            return

        for v in objs.values():
            if v.__class__.__name__ == args_list[0]:
                all_objs.append(str(v))
        print(len(all_objs))
        return

    def do_update(self, args):
        """Updates an instance based on the class name and id by adding or updating attribute

        Usage:
                update <class name> <id> <attribute name> '<attribute value>'"""

        if args == '':
            print("** class name missing **")
            return

        args_list = args.split(" ")

        if args_list[0] not in globals().keys():
            print("** class doesn't exist **")
            return

        if len(args_list) < 2:
            print("** instance id missing **")
            return

        k = f"{args_list[0]}.{args_list[1]}"
        objs = storage.all()

        if k not in objs.keys():
            print("** no instance found **")
            return

        if len(args_list) < 3:
            print("** attribute name missing **")
            return

        if len(args_list) < 4:
            print("** value missing **")
            return

        value = args_list[3]

        attr = args_list[2]
        v = ""
        if value[0] == '"' or value[0] == "'":
            if value[-1] == '"' or value[-1] == "'":
                value = value[1:-1]
        elif '.' in value:
            value = float(value)
        else:
            value = int(value)
        obj = objs[k]
        setattr(obj, attr, value)
        obj.save()

    def emptyline(self) -> bool:
        pass


    # def onecmd(self, line: str) -> bool:
    #     commands = self.parseline(line)
    #     if commands[0] not in globals().keys():
    #         return super().onecmd(line)
    #     else:
    #         c = ''
    #         i = 0
    #         for a in commands[1]:
    #             if a != '.' and a!= '(' and a != ')':
    #                 c += a
    #                 i += 1
    #         func = getattr(self, f"do_{c}")
    #         func(commands[0])

    def onecmd(self, line):
        """Interpret the argument as though it had been typed in response
        to the prompt.
        Checks whether this line is typed at the normal prompt or in
        a breakpoint command list definition.
        """
        try:
            classname = ''
            command = ''
            if '.' not in line:
                command, classname = line.split(' ')
            else:
                classname, command = line.split('.')
            if classname not in globals():
                return cmd.Cmd.onecmd(self, line)
            else:
                if command == 'all()' or command == 'all':
                    self.do_all(classname)
                    return
                elif command == 'count()' or command == 'count':
                    counter = 0
                    all_objs = models.storage.all()
                    for k in all_objs.keys():
                        key = k.split('.')
                        if key[0] == classname:
                            counter += 1
                    print(counter)
                    return
                else:
                    raw = command[command.find('(')+1:command.find(')')]
                    raw = raw.split(', ')
                    id = raw[0][1:-1]
                    c = command[0: command.find('(')]
                    cm = "{} {} {} {}".format(c, classname, id.replace('"', ''),
                                            " ".join(raw[1:]))
                    return cmd.Cmd.onecmd(self, cm)
        except:
            return cmd.Cmd.onecmd(self, line)


if __name__ == "__main__":
    Console().cmdloop()
