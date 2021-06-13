import json
import sys

# Read program tree and patterns
with open(sys.argv[1]) as f,  open(sys.argv[2]) as v:
    program = json.load(f)
    patterns = json.load(v)

class Vuln:
    def __init__(self, pattern, source):
        self.pattern = pattern
        self.sources = [source]
        self.sanitizers = []
        self.sinks = []
        self.tainted = []

currentVulns = []

# Returns name of expression
def expressionName(expression):
    if expression['type'] == 'Identifier':
        return expression['name']
    elif expression['type'] == 'Literal':
        return expression['value']
    else:
        return expressionName(expression['object']) + '.' + expressionName(expression['property'])
    

# Propagates taintedness on assignment
def checkAssignment(expression):
    global currentVulns

    leftTainted = checkExpression(expression['left'])
    rightTainted = checkExpression(expression['right'])

    leftName = expressionName(expression['left'])

    for vuln in rightTainted:
        if vuln not in leftTainted:
            vuln.tainted.append(leftName)
            if leftName in vuln.pattern['sinks'] and leftName not in vuln.sinks:
                vuln.sinks.append(leftName)

    for vuln in leftTainted:
        if vuln not in rightTainted and leftName in vuln.tainted:
            vuln.tainted.remove(leftName)


# Returns list of vulnerabilities which have tainted the expression
def checkExpression(expression):
    global currentVulns

    if expression['type'] == 'BinaryExpression':
        return checkExpression(expression['left']) + checkExpression(expression['right'])
    elif expression['type'] == 'Literal':
        return []
    elif expression['type'] == 'Identifier' or expression['type'] == 'MemberExpression':
        taintedVulns = []
        name = expressionName(expression)

        # Check if it's source
        for pattern in patterns:
            if name in pattern['sources']:
                vuln = Vuln(pattern, name) 
                taintedVulns.append(vuln)
                currentVulns.append(vuln)

        # Check if tainted by existing vulnerability
        for vuln in currentVulns:
            if name in vuln.tainted:
                taintedVulns.append(vuln)

        return taintedVulns
    elif expression['type'] == 'CallExpression':
        return checkCall(expression)
    else:
        return []




# Returns list of vulnerabilities which have tainted the call
def checkCall(expression):
    global currentVulns
    taintedVulns = []

    name = expressionName(expression['callee'])

    # Check if it's source
    newVuln = None
    for pattern in patterns:
        if name in pattern['sources']:
            newVuln = Vuln(pattern, name)
            currentVulns.append(newVuln)
            taintedVulns.append(newVuln)

    # Vulnerabilities that taint any of the arguments taint the call as well
    for argument in expression['arguments']:
        for vuln in checkExpression(argument):

            if name in vuln.pattern['sanitizers'] and name not in vuln.sanitizers:
                vuln.sanitizers.append(name)

            elif name in vuln.pattern['sinks'] and name not in vuln.sinks:
                vuln.sinks.append(name)

            # If call is a source of a vulnerability in its arguments
            # Merge source into existing vulnerability instead of creating a new one
            elif name in vuln.pattern['sources'] and name not in vuln.sources:
                vuln.sources.append(name)
                if newVuln is not None:
                    taintedVulns.remove(newVuln)
                    currentVulns.remove(newVuln)

            taintedVulns.append(vuln)

    return taintedVulns

# When two expressions are the same they must have the same vulnerabilities
def applyEquality(expression):
    leftTainted = checkExpression(expression['left'])
    rightTainted = checkExpression(expression['right'])

    for vuln in leftTainted:
        if vuln not in rightTainted:
            vuln.tainted.append(expressionName(expression['right']))

    for vuln in rightTainted:
        if vuln not in leftTainted:
            vuln.tainted.append(expressionName(expression['left']))


# Runs through a body to track vulnerabilities
def checkBody(body):
    global currentVulns
    for element in body:

        if element['type'] == 'FunctionDeclaration':
            checkBody(element['body']['body'])

        if element['type'] == 'ExpressionStatement':

            if element['expression']['type'] == 'AssignmentExpression':
                checkAssignment(element['expression'])
            elif element['expression']['type'] == 'CallExpression':
                checkCall(element['expression'])

        elif element['type'] == 'WhileStatement':
            checkExpression(element['test'])

            if element['test']['type'] == 'BinaryExpression' and element['test']['operator'] == '==':
                applyEquality(element['test'])

            for i in element['body']['body']:
                checkBody(element['body']['body'])

        elif element['type'] == 'IfStatement':
            checkExpression(element['test'])
            tmpvulns = currentVulns.copy()

            if element['test']['type'] == 'BinaryExpression' and element['test']['operator'] == '==':
                applyEquality(element['test'])

            checkBody(element['consequent']['body'])

            ifvulns = [item for item in currentVulns if item not in tmpvulns and item != []]
            currentVulns = tmpvulns

            if element['alternate'] is not None:
               checkBody(element['alternate']['body'])

            currentVulns = currentVulns + ifvulns


def outputJson(output):
    outName = sys.argv[1].split('.')[0] + '.output.json'
    with open(outName, 'w') as outfile:
        json.dump(output, outfile)

if __name__ == '__main__':
    output = []
    checkBody(program['body'])
    for vuln in currentVulns:
        if vuln.sinks:
            output.append({'vulnerability': vuln.pattern['vulnerability'], 'sources': vuln.sources, 'sanitizers': vuln.sanitizers, 'sinks': vuln.sinks})
    outputJson(output)

