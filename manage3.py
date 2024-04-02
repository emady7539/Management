import matplotlib.pyplot as plt

from pysnmp.hlapi import *
import time

# Initialize a dictionary to store the count of each object
object_counts = {}

oids = [".1.3.6.1.2.1.1.4", ".1.3.6.1.2.1.1.5", ".1.3.6.1.2.1.1.6"]

def get_oid(ip_address, oid):
    # Increment the count of the object
    object_counts[oid] = object_counts.get(oid, 0) + 1

    # Create a GET request
    error_indication, error_status, error_index, var_binds = next(
        getCmd(
            SnmpEngine(),
            CommunityData('ym2'),
            UdpTransportTarget((ip_address, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        )
    )

    if error_indication:
        print(error_indication)
    else:
        if error_status:
            print('%s at %s' % (error_status.prettyPrint(), error_index and var_binds[int(error_index) - 1][0] or '?'))
        else:
            for var_bind in var_binds:
                print(' = '.join([x.prettyPrint() for x in var_bind]))

def set_oid(ip_address, oid, value):
    # Increment the count of the object
    object_counts[oid] = object_counts.get(oid, 0) + 1

    # Create a SET request
    error_indication, error_status, error_index, var_binds = next(
        setCmd(
            SnmpEngine(),
            CommunityData('ym2'),
            UdpTransportTarget((ip_address, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid), OctetString(value)),
            lexicographicMode=False,
        )
    )

    if error_indication:
        print(error_indication)
    else:
        if error_status:
            print('%s at %s' % (error_status.prettyPrint(), error_index and var_binds[int(error_index) - 1][0] or '?'))
        else:
            print('Value set successfully')

def getnext_oid(ip_address, oid):
    # Increment the count of the object
    object_counts[oid] = object_counts.get(oid, 0) + 1

    # Create a GETNEXT request
    error_indication, error_status, error_index, var_binds = next(
        nextCmd(
            SnmpEngine(),
            CommunityData('ym2'),
            UdpTransportTarget((ip_address, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        )
    )

    if error_indication:
        print(error_indication)
    else:
        if error_status:
            print('%s at %s' % (error_status.prettyPrint(), error_index and var_binds[int(error_index) - 1][0] or '?'))
        else:
            for var_bind in var_binds:
                print(' = '.join([x.prettyPrint() for x in var_bind]))

def handle_threshold(oid, threshold):
    value = get_oid(ip_address, oid)
    if value is not None and value >= threshold:
        if oid == ".1.3.6.1.2.1.1.5":  # Example: Display a notification for sysName
            print(f"Threshold reached for sysName: {value}")
            # Display a notification on the NMS browser
            # Here, you can implement a custom notification system using a web framework
            # or a third-party library.

        elif oid == ".1.3.6.1.2.1.1.4":  # Example: Set a parameter on the managed device for sysLocation
            set_oid(ip_address, ".1.3.6.1.2.1.1.6", "NewLocation")
            print(f"Threshold reached for sysLocation: {value}. New value set for sysLocation.")

ip_address = "localhost"

for oid in oids:
    get_oid(ip_address, oid)

handle_threshold(oids[1], 50)

set_oid(ip_address, oids[0], "new_value")

time.sleep(1)

value = get_oid(ip_address, oids[0])

getnext_oid(ip_address, oids[0])

value = get_oid(ip_address, oids[0])

oids.append(".1.3.6.1.2.1.1.5")

handle_threshold(oids[3], 50)

# Manage objects...

# Plot the counts of the objects
objects = list(object_counts.keys())
counts = list(object_counts.values())
plt.bar(objects, counts)
plt.xlabel('Objects')
plt.ylabel('Count')
plt.title('Number of times each object has been managed')
plt.show()