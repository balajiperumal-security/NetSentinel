def explain_risk(risk, port, count):
    print("\n" + "=" * 55)
    print("          NETSENTINEL RESPONSE ENGINE")
    print("=" * 55)

    print(f"\nRisk Level : {risk}")
    print(f"Port       : {port}")
    print(f"Events     : {count}")

    if risk == "HIGH":
        print("\nExplanation:")
        print("High traffic activity was detected on this port.")

        print("\nRecommended Action:")
        print("Review the source and destination before taking action.")
        print("Use approved firewall rules if the activity is confirmed unwanted.")

    elif risk == "MEDIUM":
        print("\nExplanation:")
        print("Repeated network activity was detected.")

        print("\nRecommended Action:")
        print("Continue monitoring and investigate the source.")

    else:
        print("\nExplanation:")
        print("The observed traffic is within the current monitoring threshold.")

        print("\nRecommended Action:")
        print("Continue monitoring normally.")

    print("\nVerification:")
    print("Monitor subsequent traffic to confirm whether the activity continues.")
    print("=" * 55)


# Demo using the current low-risk result
explain_risk("LOW", "80", 4)
