import { PrismaClient, SubjectCategory, Confidence } from "@prisma/client";

const prisma = new PrismaClient();

const subjects = [
  "Eulen",
  "RedEngine",
  "Lynx",
  "Brutan",
  "Dopamine",
  "FiveSense",
  "Hydro",
  "Lumia",
  "Maestro",
  "Phoenix",
  "TiagoMenu",
  "WolfMenu",
  "Fallout",
  "Alien Menu",
  "Cobra",
  "ChronoPulse",
  "Hoax"
];

async function main() {
  for (const name of subjects) {
    await prisma.subject.upsert({
      where: { name },
      update: {},
      create: {
        name,
        category: SubjectCategory.FIVEM_CHEAT,
        confidence: Confidence.UNVERIFIED,
        description:
          "Seed subject only. Verify the exact Discord server ID, ownership, category, and source before treating as a confirmed community."
      }
    });
  }
  console.log(`Seeded ${subjects.length} subjects.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
