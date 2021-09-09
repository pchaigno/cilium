#!/usr/bin/env python3
from enum import Enum
import sys

class Condition(Enum):
    OR = 1
    REQUIRES = 2
    PRESENT = 3
    EITHER = 4

options = []
conditions = []

def is_power_of_two_or_zero(x):
    return (x & (x - 1)) == 0

def parse_combination(tokens, options):
    combination = 0
    for i in range(len(options)):
        for token in tokens:
            # print("%s == %s" % (options[i], token))
            if options[i] == token.rstrip():
                # print("adding %d from %s" % (2**i, token))
                combination += 2**i
    return combination

def print_combination(combination, options):
    string = format(combination, '#0%db' % 64)
    string = string[2:]
    # print(string)
    for i in range(len(options)):
        if string[-i-1] == '1':
            print("%s " % options[i], end='')
    print()

def print_condition(condition, options):
    if condition[0] == Condition.OR:
        print("or %s" % print_combination(condition[2], options))
    if condition[0] == Condition.PRESENT:
        print("present %s" % print_combination(condition[2], options))
    if condition[0] == Condition.EITHER:
        print("either %s" % print_combination(condition[2], options))
    if condition[0] == Condition.REQUIRES:
        print("requires %s" % (print_combination(condition[1], options), print_combination(condition[2], options)))


def match_condition(combination, condition):
    if condition[0] == Condition.OR or condition[0] == Condition.PRESENT:
        # print("%d & %d != 0" % (combination, condition[1]))
        return combination & condition[2] != 0
    elif condition[0] == Condition.REQUIRES:
        # print("(%d & %d == 0) or (%d & %d == %d)" % (combination, condition[1], combination, condition[2], condition[2]))
        return (combination & condition[1] == 0) or (combination & condition[2] == condition[2])
    elif condition[0] == Condition.EITHER:
        return is_power_of_two_or_zero(combination & condition[2])
    return True

def match_conditions(combination, conditions, options):
    for condition in conditions:
        if not match_condition(combination, condition):
            # print("%d doesn't match %s" % (combination, print_condition(condition, options)))
            return False
    return True

def explore_combinations(options, conditions):
    max_combi = 2**len(options)-1
    next_percent = 1
    next_percent_value = int(next_percent/100.0*max_combi)
    for combination in range(1, max_combi, 1):
        if combination == next_percent_value:
            print("%d/%d (%d%%)" % (combination, max_combi, next_percent), file=sys.stderr)
            next_percent += 1
            next_percent_value = int(next_percent/100.0*max_combi)
        if match_conditions(combination, conditions, options):
            print_combination(combination, options)

if __name__ == "__main__":
    with open('options.txt') as f:
        for line in f:
            if line.startswith('#'):
                continue
            options.append(line.rstrip())

    with open('conditions.txt') as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            if line.startswith('#'):
                continue
            tokens = line.split(' ')
            if tokens[0] == 'or':
                combination = parse_combination(tokens[1:], options)
                conditions.append((Condition.OR, 0, combination))
            elif tokens[0] == 'requires':
                subject = parse_combination([tokens[1]], options)
                combination = parse_combination(tokens[2:], options)
                conditions.append((Condition.REQUIRES, subject, combination))
            elif tokens[0] == 'either':
                combination = parse_combination(tokens[1:], options)
                conditions.append((Condition.EITHER, 0, combination))
            elif len(tokens) == 1:
                combination = parse_combination(tokens, options)
                conditions.append((Condition.PRESENT, 0, combination))

    explore_combinations(options, conditions)
