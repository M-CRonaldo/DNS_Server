"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ip = "198.41.0.4"
ccname = ""

# current as of 23 February 2017
ROOT_SERVERS = ("198.41.0.4",
                "192.228.79.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    fllresponse = {}

    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME, ip)
    cnames = []
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": name})
    # lookup A
    response = lookup(target_name, dns.rdatatype.A, ip)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA, ip)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX, ip)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    if (not arecords and not aaaarecords and not mxrecords and cnames):
        cname = str(cnames)
        cnamesplit = cname.split("rdata: ")
        cnamesplit1 = cnamesplit[1].split(".>,")
        target_name = str(cnamesplit1[0])
        #print(target_name)

        # lookup A
        response = lookup(target_name, dns.rdatatype.A, ip)
        arecords = []
        for answers in response.answer:
            a_name = answers.name
            for answer in answers:
                if answer.rdtype == 1:  # A record
                    arecords.append({"name": a_name, "address": str(answer)})
        # lookup AAAA
        response = lookup(target_name, dns.rdatatype.AAAA, ip)
        aaaarecords = []
        for answers in response.answer:
            aaaa_name = answers.name
            for answer in answers:
                if answer.rdtype == 28:  # AAAA record
                    aaaarecords.append({"name": aaaa_name, "address": str(answer)})
        # lookup MX
        response = lookup(target_name, dns.rdatatype.MX, ip)
        mxrecords = []
        for answers in response.answer:
            mx_name = answers.name
            for answer in answers:
                if answer.rdtype == 15:  # MX record
                    mxrecords.append({"name": mx_name,
                                      "preference": answer.preference,
                                      "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def lookupfinally(target_name: dns.name.Name,
                  qtype: dns.rdata.Rdata, ip) -> dns.message.Message:

    outbound_query = dns.message.make_query(target_name, qtype)
    response = dns.query.udp(outbound_query, ip, 3)
    return response


def lookup1(target_name: dns.name.Name,
            qtype: dns.rdata.Rdata, ip) -> dns.message.Message:

    outbound_query = dns.message.make_query(target_name, qtype)
    response = dns.query.udp(outbound_query, ip, 3)
    return response


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata, ip) -> dns.message.Message:

    outbound_query = dns.message.make_query(target_name, qtype)
    response = dns.query.udp(outbound_query, ip, 3)

    if (len(response.answer) > 0):
        return response
    elif (len(response.additional) > 0):
        for addis in response.additional:
            a_name = addis.name
            for addi in addis:
                if addi.rdtype == 1:
                    response = lookup1(target_name, dns.rdatatype.A, str(addi))
                    if (len(response.answer) > 0):
                        response = lookupfinally(target_name, qtype, str(addi))
                        return response
                    elif(len(response.additional) > 0):
                        for addis1 in response.additional:
                            a_name = addis1.name
                            for addi1 in addis1:
                                if addi1.rdtype == 1:
                                    response = lookup1(
                                        target_name, dns.rdatatype.A, str(addi1))
                                    if (len(response.answer) > 0):
                                        response = lookupfinally(
                                            target_name, qtype, str(addi1))
                                        return response
                                    elif(len(response.additional) > 0):
                                        for addis2 in response.additional:
                                            a_name = addis2.name
                                            for addi2 in addis2:
                                                if addi2.rdtype == 1:
                                                    response = lookup1(
                                                        target_name, dns.rdatatype.A, str(addi2))
                                                    if (len(response.answer) > 0):
                                                        response = lookupfinally(
                                                            target_name, qtype, str(addi2))
                                                        return response
                                                    elif(len(response.additional) > 0):
                                                        for addis3 in response.additional:
                                                            a_name = addis3.name
                                                            for addi3 in addis3:
                                                                if addi3.rdtype == 1:
                                                                    response = lookup1(
                                                                        target_name, dns.rdatatype.A, str(addi3))
                                                                    if (len(response.answer) > 0):
                                                                        response = lookupfinally(
                                                                            target_name, qtype, str(addi3))
                                                                        return response
    # print(response)
    return response


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))


if __name__ == "__main__":
    main()
